#include <memory>
#include <random>

#include "../include/tfhe++.hpp"

int main()
{
    // Generate a random key.
    double sk_start = get_time_msec();
    std::cout << "secret key starts." << std::endl;
    const std::unique_ptr<TFHEpp::SecretKey> sk(new TFHEpp::SecretKey());
    std::cout << "time for generating sk is " << get_time_msec() - sk_start
              << std::endl;

    double ek_start = get_time_msec();
    TFHEpp::EvalKey ek;
    ek.emplaceiksk<TFHEpp::lvl10param>(*sk);
    ek.emplacebkfft<TFHEpp::lvl01param>(*sk);
    std::cout << "time for generating ek is " << get_time_msec() - ek_start
              << std::endl;
    
    int vector_size =100;
    std::vector<double> p(vector_size);
    for (int i = 0; i < vector_size; i++) {
        p[i] = 1;
    }
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);

    std::vector<TFHEpp::TLWE<TFHEpp::lvl0param>> ca(vector_size); 
    double encryption_start = get_time_msec();
    for (int i = 0; i < vector_size; i++) {
        ca[i] =
        TFHEpp::tlweSymEncrypt<TFHEpp::lvl0param>(
            binary(engine), TFHEpp::lvl0param::α, sk->key.lvl0);
    }
    std::cout << "time for encryption is " << get_time_msec() - encryption_start
              << std::endl;

    return 0;
}