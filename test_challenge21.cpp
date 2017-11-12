// Compile with: g++ test_challenge21.cpp -o test_challenge21
#include <iostream>
#include <random>

using namespace std;

int main(int argc, const char* argv[]) {
  if (argc < 2) {
    printf("Usage: test_challenge21 <seed> <number of consecutive random numbers>\n");
  } else {
    int seed = atoi(argv[1]);
    int N = atoi(argv[2]);

    mt19937 mt_rand(seed);
    for (size_t i = 0; i < N; ++i) {
      cout << mt_rand() << endl;
    }
  }
}

