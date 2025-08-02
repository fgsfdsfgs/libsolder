#include <string.h>
#include <limits.h>

#include "common.h"
#include "solder.h"
#include "util.h"
#include "lookup.h"
#include "tls.h"
#include "reloc.h"

static int process_relocs(dynmod_t *mod, const Elf64_Rela *rels, const size_t num_rels, const int imports_only, const int ignore_undef) {
  int num_failed = 0;

  for (size_t j = 0; j < num_rels; j++) {
    uintptr_t *ptr = (uintptr_t *)((uintptr_t)mod->load_virtbase + rels[j].r_offset);
    const uintptr_t symno = ELF64_R_SYM(rels[j].r_info);
    const int type = ELF64_R_TYPE(rels[j].r_info);
    uintptr_t symval = 0;
    uintptr_t symbase = (uintptr_t)mod->load_virtbase;
    const char *symname = NULL;

    if (symno) {
      // if the reloc refers to a symbol, get the symbol value in there
      const Elf64_Sym *sym = &mod->dynsym[symno];
      if (sym->st_shndx == SHN_UNDEF) {
        symname = mod->dynstrtab + sym->st_name;
        // HACK: patch references to __aarch64_read_tp if this is it and we have a replacement
        if (mod->readtp_virtbase && !strcmp(symname, "__aarch64_read_tp")) {
          symval = (uintptr_t)mod->readtp_virtbase;
          DEBUG_PRINTF("`%s`: patching ref to `%s` at %p to %p\n", mod->name, symname, ptr, (void *)symval);
        } else {
          symval = (uintptr_t)solder_lookup_global(symname);
        }
        symbase = 0; // symbol is somewhere else
        if (!symval) {
          const int weak = (ELF64_ST_BIND(sym->st_info) == STB_WEAK);
          if (weak || ignore_undef) {
            // ignore resolution failure for weak syms or if we don't care
            DEBUG_PRINTF("`%s`: resolution failed for `%s`%s\n", mod->name, symname, weak ? " (weak)" : "");
            continue;
          } else {
            solder_set_error("`%s`: Could not resolve symbol: `%s`", mod->name, symname);
            ++num_failed;
          }
        }
      } else {
        if (imports_only) continue;
        symval = sym->st_value;
      }
    } else if (imports_only) {
      continue;
    }

    switch (type) {
      case R_AARCH64_RELATIVE:
        // sometimes the value of r_addend is also at *ptrs
        *ptr = symbase + rels[j].r_addend;
        break;
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        *ptr = symbase + symval + rels[j].r_addend;
        break;
      case R_AARCH64_TLS_TPREL64:
        // ignore it and hope for the best
        DEBUG_PRINTF("`%s`: R_AARCH64_TLS_TPREL64 relocation ignored\n", mod->name);
        break;
      case R_AARCH64_TLSDESC:
        // give it our dumb TLS resolver and hope it works
        *ptr = (uintptr_t)solder_tls_resolve_tlsdesc;
        DEBUG_PRINTF("`%s`: R_AARCH64_TLSDESC relocation at %p\n", mod->name, ptr);
        break;
      case R_AARCH64_NONE:
        break; // sorry nothing
      default:
        solder_set_error("`%s`: Unknown relocation type: %d", mod->name, type);
        return -1;
    }
  }

  return num_failed;
}

int solder_relocate(dynmod_t *mod, const int ignore_undef, const int imports_only) {
  Elf64_Rela *rela = NULL;
  Elf64_Relr *relr = NULL;
  Elf64_Rela *jmprel = NULL;
  void **tlsdesc_plt = NULL;
  void **tlsdesc_got = NULL;
  uint32_t pltrel = 0;
  size_t relasz = 0;
  size_t relrsz = 0;
  size_t pltrelsz = 0;

  // allocate space in the main module's TLS for this module's TLS, if needed
  if (!mod->tls_size && !imports_only)
    solder_tls_alloc(mod);

  // find RELA and JMPREL
  for (Elf64_Dyn *dyn = mod->dynamic; dyn->d_tag != DT_NULL; dyn++) {
    switch (dyn->d_tag) {
      case DT_RELA:
        rela = (Elf64_Rela *)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_RELR:
        relr = (Elf64_Relr *)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_RELRSZ:
        relrsz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        // TODO: don't assume RELA
        jmprel = (Elf64_Rela *)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_PLTREL:
        pltrel = dyn->d_un.d_val;
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      case DT_TLSDESC_GOT:
        tlsdesc_got = (void **)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      case DT_TLSDESC_PLT:
        tlsdesc_plt = (void **)(mod->load_virtbase + dyn->d_un.d_ptr);
        break;
      default:
        break;
    }
  }

  if (tlsdesc_got && tlsdesc_plt) {
    // tls trampoline in PLT calling a function pointer in GOT; provide that pointer
    DEBUG_PRINTF("`%s`: TLS trampoline calling %p (%p)\n", mod->name, tlsdesc_got, *tlsdesc_got);
    *tlsdesc_got = solder_tls_resolve_static;
  }

  if (rela && relasz) {
    DEBUG_PRINTF("`%s`: processing RELA@%p size %lu\n", mod->name, rela, relasz);
    // if there are any unresolved imports, bail unless it's the final relocation pass
    if (process_relocs(mod, rela, relasz / sizeof(Elf64_Rela), imports_only, ignore_undef))
      return -1;
  }

  if (relr && relrsz) {
    DEBUG_PRINTF("`%s`: processing RELR@%p size %lu\n", mod->name, relr, relrsz);
    const Elf64_Relr *relrend = relr + relrsz / sizeof(Elf64_Relr);
    uintptr_t *loc = NULL;
    for (; relr < relrend; ++relr) {
      Elf64_Relr entry = *relr;
      if ((entry & 1) == 0) {
        loc = (uintptr_t *)(mod->load_virtbase + entry);
        *loc++ += (uintptr_t)mod->load_virtbase;
      } else {
        for (intptr_t i = 0; (entry >>= 1) != 0; ++i) {
          if (entry & 1)
            loc[i] += (uintptr_t)mod->load_virtbase;
        }
        loc += CHAR_BIT * sizeof(Elf64_Relr) - 1;
      }
    }
  }

  if (jmprel && pltrelsz && pltrel) {
    // TODO: support DT_REL
    if (pltrel == DT_RELA) {
      DEBUG_PRINTF("`%s`: processing JMPREL@%p size %lu\n", mod->name, jmprel, pltrelsz);
      // if there are any unresolved imports, bail unless it's the final relocation pass
      if (process_relocs(mod, jmprel, pltrelsz / sizeof(Elf64_Rela), imports_only, ignore_undef))
        return -1;
    } else {
      DEBUG_PRINTF("`%s`: DT_JMPREL has unsupported type %08x\n", mod->name, pltrel);
    }
  }

  if (mod->type == ET_EXEC) {
    // HACKHACKHACK: ET_EXECs are probably not relocatable; but we'll try anyway
    // relocate the basic stuff, let the user worry about everything else
    if (mod->init_array && mod->num_init) {
      for (size_t i = 0; i < mod->num_init; ++i)
        if ((void *)mod->init_array[i] >= mod->vma_start && (void *)mod->init_array[i] < mod->vma_start + mod->vma_size)
          mod->init_array[i] +=  (uintptr_t)mod->load_virtbase;
    }
    if (mod->fini_array && mod->num_fini) {
      for (size_t i = 0; i < mod->num_fini; ++i)
        if ((void *)mod->fini_array[i] >= mod->vma_start && (void *)mod->fini_array[i] < mod->vma_start + mod->vma_size)
          mod->fini_array[i] +=  (uintptr_t)mod->load_virtbase;
    }
    if (mod->got && mod->num_got) {
      for (size_t i = 0; i < mod->num_got; ++i) {
        if (mod->got[i] >= mod->vma_start && mod->got[i] < mod->vma_start + mod->vma_size)
          mod->got[i] += (uintptr_t)mod->load_virtbase;
      }
    }
  }

  mod->flags |= MOD_RELOCATED;

  return 0;
}
