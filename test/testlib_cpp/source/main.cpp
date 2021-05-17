#include <iostream>
#include <vector>
#include <string>
#include <exception>

extern "C" float crosslink_this(const char *str, float x, float y);

class CTest {
public:
  virtual int test(float x) = 0;
};

class CTestGood : public CTest {
public:
  CTestGood(const char *_arse) : arse(_arse) { }

  virtual int test(float x) override {
    std::cout << arse << std::endl;
    std::vector<float> v = { 6.f, 9.f };
    float result = crosslink_this("sneed", v[0], v[1]);
    std::cout << "yes, the result is indeed " << result << std::endl;
    return 5643;
  }

private:
  std::string arse;
};

class CTestBad : public CTest {
public:
  virtual int test(float x) override {
    std::cout << "nope" << std::endl;
    return -666;
  }
};

static CTest *test_object[] = {
  new CTestGood("sneed's feed and seed"),
  new CTestBad()
};

extern "C" int test_cpp(int index, float x) {
  if (index < 0 || index > 1) {
    std::cerr << "index bad" << std::endl;
    return -1;
  }
  CTest *test_ref = test_object[index];
  return test_ref->test(x);
}
