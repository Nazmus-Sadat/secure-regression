#include <algorithm>
//#include <stl/_map.h>
#include <stdint.h>
#include "chooser.h"
#include "utilities.h"
#include "util/uintarith.h"
#include "util/uintextras.h"

using namespace std;
using namespace seal::util;

namespace seal
{
	/*
    const map<int, BigUInt> ChooserEvaluator::default_parameter_options_
    {
        { 1024, BigUInt("FFFFFFFFC001") },
        { 2048, BigUInt("7FFFFFFFFFFFFFFFFFFF001") },
        { 4096, BigUInt("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") },
        { 8192, BigUInt("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC000001") },
        { 16384, BigUInt("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000001") }
    };
	*/
    const double ChooserEvaluator::default_noise_standard_deviation_ = 3.19;

    ChooserPoly::ChooserPoly() : max_coeff_count_(0), max_abs_value_(), comp_(nullptr)
    {
    }

    ChooserPoly::ChooserPoly(int max_coeff_count, const BigUInt &max_abs_value) :
        max_coeff_count_(max_coeff_count), max_abs_value_(max_abs_value), comp_(new FreshComputation())
    {
        if (max_coeff_count <= 0)
        {
            throw invalid_argument("max_coeff_count must be strictly positive");
        }
        if (max_abs_value.is_zero())
        {
            max_coeff_count_ = 1;
        }
    }

    ChooserPoly::ChooserPoly(int max_coeff_count, uint64_t max_abs_value) :
        max_coeff_count_(max_coeff_count), comp_(new FreshComputation())
    {
        if (max_coeff_count <= 0)
        {
            throw invalid_argument("max_coeff_count must be strictly positive");
        }
        if (max_abs_value == 0)
        {
            max_coeff_count_ = 1;
        }
        BigUInt max_abs_value_uint;
        max_abs_value_uint = max_abs_value;
        max_abs_value_ = max_abs_value_uint;
    }

    ChooserPoly::ChooserPoly(int max_coeff_count, const BigUInt &max_abs_value, Computation *comp) :
        max_coeff_count_(max_coeff_count), max_abs_value_(max_abs_value), comp_(comp)
    {
        if (max_coeff_count <= 0)
        {
            throw invalid_argument("max_coeff_count must be strictly positive");
        }

        if (max_abs_value.is_zero())
        {
            max_coeff_count_ = 1;
        }

        /*
        if (comp == nullptr)
        {
            comp_ = new FreshComputation();
        }
        */
    }

    ChooserPoly::ChooserPoly(int max_coeff_count, uint64_t max_abs_value, Computation *comp) :
        max_coeff_count_(max_coeff_count), comp_(comp)
    {
        if (max_coeff_count <= 0)
        {
            throw invalid_argument("max_coeff_count must be strictly positive");
        }
        if (max_abs_value == 0)
        {
            max_coeff_count_ = 1;
        }
        BigUInt max_abs_value_uint;
        max_abs_value_uint = max_abs_value;
        max_abs_value_ = max_abs_value_uint;
        /*
        if (comp == nullptr)
        {
            comp_ = new FreshComputation();
        }
        */
    }

    ChooserPoly::~ChooserPoly()
    {
        reset();
    }

    ChooserPoly::ChooserPoly(const ChooserPoly &copy) : max_coeff_count_(0), max_abs_value_(), comp_(nullptr)
    {
        operator =(copy);
    }

    ChooserPoly &ChooserPoly::operator =(const ChooserPoly &assign)
    {
        reset();
        if (assign.comp_ != nullptr)
        {
            comp_ = assign.comp_->clone();
        }
        max_abs_value_ = assign.max_abs_value_;
        max_coeff_count_ = assign.max_coeff_count_;

        return *this;
    }

    ChooserPoly ChooserEvaluator::add(const ChooserPoly &operand1, const ChooserPoly &operand2)
    {
        if (operand1.max_coeff_count_ <= 0 || operand1.comp_ == nullptr)
        {
            throw invalid_argument("operand1 is not correctly initialized");
        }
        if (operand2.max_coeff_count_ <= 0 || operand2.comp_ == nullptr)
        {
            throw invalid_argument("operand2 is not correctly initialized");
        }

        return ChooserPoly(max(operand1.max_coeff_count_, operand2.max_coeff_count_), operand1.max_abs_value_ + operand2.max_abs_value_, new AddComputation(*operand1.comp_, *operand2.comp_));
    }

    ChooserPoly ChooserEvaluator::add_many(const std::vector<ChooserPoly> &operands)
    {
        if (operands.empty())
        {
            throw invalid_argument("operands vector can not be empty");
        }

        int sum_max_coeff_count = operands[0].max_coeff_count_;
        vector<ChooserPoly>::size_type largest_abs_value_index = 0;
        for (vector<ChooserPoly>::size_type i = 0; i < operands.size(); ++i)
        {
            // Throw if any of the operands is not initialized correctly
            if (operands[i].max_coeff_count_ <= 0 || operands[i].comp_ == nullptr)
            {
                throw invalid_argument("input operand is not correctly initialized");
            }

            if (operands[i].max_coeff_count_ > sum_max_coeff_count)
            {
                sum_max_coeff_count = operands[i].max_coeff_count_;
            }
            if (compare_uint_uint(operands[i].max_abs_value_.pointer(), operands[i].max_abs_value_.uint64_count(), operands[largest_abs_value_index].max_abs_value_.pointer(), operands[largest_abs_value_index].max_abs_value_.uint64_count() > 0))
            {
                largest_abs_value_index = i;
            }
        }

        int sum_max_abs_value_bit_count = operands[largest_abs_value_index].max_abs_value_.significant_bit_count() + get_significant_bit_count(operands.size());
        int sum_max_abs_value_uint64_count = divide_round_up(sum_max_abs_value_bit_count, bits_per_uint64);
        Pointer sum_max_abs_value(allocate_zero_uint(sum_max_abs_value_uint64_count, pool_));

        vector<Computation*> comps;
        for (vector<ChooserPoly>::size_type i = 0; i < operands.size(); ++i)
        {
            add_uint_uint(operands[i].max_abs_value_.pointer(), operands[i].max_abs_value_.uint64_count(), sum_max_abs_value.get(), sum_max_abs_value_uint64_count, false, sum_max_abs_value_uint64_count, sum_max_abs_value.get());
            comps.push_back(operands[i].comp_);
        }

        return ChooserPoly(sum_max_coeff_count, BigUInt(sum_max_abs_value_bit_count, sum_max_abs_value.get()), new AddManyComputation(comps));
    }

    ChooserPoly ChooserEvaluator::sub(const ChooserPoly &operand1, const ChooserPoly &operand2)
    {
        if (operand1.max_coeff_count_ <= 0 || operand1.comp_ == nullptr)
        {
            throw invalid_argument("operand1 is not correctly initialized");
        }
        if (operand2.max_coeff_count_ <= 0 || operand2.comp_ == nullptr)
        {
            throw invalid_argument("operand2 is not correctly initialized");
        }

        return ChooserPoly(max(operand1.max_coeff_count_, operand2.max_coeff_count_), operand1.max_abs_value_ + operand2.max_abs_value_, new SubComputation(*operand1.comp_, *operand2.comp_));
    }

    ChooserPoly ChooserEvaluator::multiply(const ChooserPoly &operand1, const ChooserPoly &operand2)
    {
        if (operand1.max_coeff_count_ <= 0 || operand1.comp_ == nullptr)
        {
            throw invalid_argument("operand1 is not correctly initialized");
        }
        if (operand2.max_coeff_count_ <= 0 || operand2.comp_ == nullptr)
        {
            throw invalid_argument("operand2 is not correctly initialized");
        }
        if (operand1.max_abs_value_.is_zero() || operand2.max_abs_value_.is_zero())
        {
            return ChooserPoly(1, 0, new MultiplyComputation(*operand1.comp_, *operand2.comp_));
        }

        uint64_t growth_factor = min(operand1.max_coeff_count_, operand2.max_coeff_count_);
        int prod_bit_count = operand1.max_abs_value_.significant_bit_count() + operand2.max_abs_value_.significant_bit_count() + get_significant_bit_count(growth_factor) + 1;
        int prod_uint64_count = divide_round_up(prod_bit_count, bits_per_uint64);

        Pointer prod_max_abs_value(allocate_zero_uint(prod_uint64_count, pool_));
        ConstPointer wide_operand2_max_abs_value(duplicate_uint_if_needed(operand2.max_abs_value_.pointer(), operand2.max_abs_value_.uint64_count(), prod_uint64_count, false, pool_));

        multiply_uint_uint(&growth_factor, 1, operand1.max_abs_value_.pointer(), operand1.max_abs_value_.uint64_count(), prod_uint64_count, prod_max_abs_value.get());
        ConstPointer temp_pointer(duplicate_uint_if_needed(prod_max_abs_value.get(), prod_uint64_count, prod_uint64_count, true, pool_));
        multiply_uint_uint(wide_operand2_max_abs_value.get(), prod_uint64_count, temp_pointer.get(), prod_uint64_count, prod_uint64_count, prod_max_abs_value.get());

        return ChooserPoly(operand1.max_coeff_count_ + operand2.max_coeff_count_ - 1, BigUInt(prod_bit_count, prod_max_abs_value.get()), new MultiplyComputation(*operand1.comp_, *operand2.comp_));
    }

    /*
    ChooserPoly ChooserEvaluator::multiply_norelin(const ChooserPoly &operand1, const ChooserPoly &operand2)
    {
        if (operand1.max_coeff_count_ <= 0 || operand1.comp_ == nullptr)
        {
            throw invalid_argument("operand1 is not correctly initialized");
        }
        if (operand2.max_coeff_count_ <= 0 || operand2.comp_ == nullptr)
        {
            throw invalid_argument("operand2 is not correctly initialized");
        }
        if (operand1.max_abs_value_.is_zero() || operand2.max_abs_value_.is_zero())
        {
            return ChooserPoly(1, 0, new MultiplyNoRelinComputation(*operand1.comp_, *operand2.comp_));
        }

        uint64_t growth_factor = min(operand1.max_coeff_count_, operand2.max_coeff_count_);
        int prod_bit_count = operand1.max_abs_value_.significant_bit_count() + operand2.max_abs_value_.significant_bit_count() + get_significant_bit_count(growth_factor) + 1;
        int prod_uint64_count = divide_round_up(prod_bit_count, bits_per_uint64);

        Pointer prod_max_abs_value(allocate_zero_uint(prod_uint64_count, pool_));
        ConstPointer wide_operand2_max_abs_value(duplicate_uint_if_needed(operand2.max_abs_value_.pointer(), operand2.max_abs_value_.uint64_count(), prod_uint64_count, false, pool_));

        multiply_uint_uint(&growth_factor, 1, operand1.max_abs_value_.pointer(), operand1.max_abs_value_.uint64_count(), prod_uint64_count, prod_max_abs_value.get());
        ConstPointer temp_pointer(duplicate_uint_if_needed(prod_max_abs_value.get(), prod_uint64_count, prod_uint64_count, true, pool_));
        multiply_uint_uint(wide_operand2_max_abs_value.get(), prod_uint64_count, temp_pointer.get(), prod_uint64_count, prod_uint64_count, prod_max_abs_value.get());

        return ChooserPoly(operand1.max_coeff_count_ + operand2.max_coeff_count_ - 1, BigUInt(prod_bit_count, prod_max_abs_value.get()), new MultiplyNoRelinComputation(*operand1.comp_, *operand2.comp_));
    }

    ChooserPoly ChooserEvaluator::relinearize(const ChooserPoly &operand)
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }

        return ChooserPoly(operand.max_coeff_count_, operand.max_abs_value_, new RelinearizeComputation(*operand.comp_));
    }
    */

    ChooserPoly ChooserEvaluator::multiply_plain(const ChooserPoly &operand, int plain_max_coeff_count, const BigUInt &plain_max_abs_value)
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }
        if (plain_max_coeff_count <= 0)
        {
            throw invalid_argument("plain_max_coeff_count must be positive");
        }
        if (plain_max_abs_value.is_zero())
        {
            return ChooserPoly(1, 0, new MultiplyPlainComputation(*operand.comp_, plain_max_coeff_count, plain_max_abs_value));
        }
        if (operand.max_abs_value_.is_zero())
        {
            return ChooserPoly(1, 0, new MultiplyPlainComputation(*operand.comp_, plain_max_coeff_count, plain_max_abs_value));
        }

        uint64_t growth_factor = min(operand.max_coeff_count_, plain_max_coeff_count);
        int prod_bit_count = operand.max_abs_value_.significant_bit_count() + plain_max_abs_value.significant_bit_count() + get_significant_bit_count(growth_factor) + 1;
        int prod_uint64_count = divide_round_up(prod_bit_count, bits_per_uint64);

        Pointer prod_max_abs_value(allocate_zero_uint(prod_uint64_count, pool_));
        ConstPointer wide_operand_max_abs_value(duplicate_uint_if_needed(operand.max_abs_value_.pointer(), operand.max_abs_value_.uint64_count(), prod_uint64_count, false, pool_));

        multiply_uint_uint(&growth_factor, 1, plain_max_abs_value.pointer(), plain_max_abs_value.uint64_count(), prod_uint64_count, prod_max_abs_value.get());
        ConstPointer temp_pointer(duplicate_uint_if_needed(prod_max_abs_value.get(), prod_uint64_count, prod_uint64_count, true, pool_));
        multiply_uint_uint(wide_operand_max_abs_value.get(), prod_uint64_count, temp_pointer.get(), prod_uint64_count, prod_uint64_count, prod_max_abs_value.get());

        return ChooserPoly(operand.max_coeff_count_ + plain_max_coeff_count - 1, BigUInt(prod_bit_count, prod_max_abs_value.get()), new MultiplyPlainComputation(*operand.comp_, plain_max_coeff_count, plain_max_abs_value));
    }

    ChooserPoly ChooserEvaluator::multiply_plain(const ChooserPoly &operand, int plain_max_coeff_count, uint64_t plain_max_abs_value)
    {
        return multiply_plain(operand, plain_max_coeff_count, BigUInt(64, plain_max_abs_value));
    }

    ChooserPoly ChooserEvaluator::add_plain(const ChooserPoly &operand, int plain_max_coeff_count, const BigUInt &plain_max_abs_value) const
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }
        if (plain_max_coeff_count <= 0)
        {
            throw invalid_argument("plain_max_coeff_count must be positive");
        }
        if (plain_max_abs_value.is_zero())
        {
            return ChooserPoly(operand.max_coeff_count_, operand.max_abs_value_, new AddPlainComputation(*operand.comp_));
        }
        if (operand.max_abs_value_.is_zero())
        {
            return ChooserPoly(plain_max_coeff_count, plain_max_abs_value, new AddPlainComputation(*operand.comp_));
        }

        return ChooserPoly(max(operand.max_coeff_count_, plain_max_coeff_count), operand.max_abs_value_ + plain_max_abs_value, new AddPlainComputation(*operand.comp_));
    }

    ChooserPoly ChooserEvaluator::add_plain(const ChooserPoly &operand, int plain_max_coeff_count, uint64_t plain_max_abs_value)
    {
        return add_plain(operand, plain_max_coeff_count, BigUInt(64, plain_max_abs_value));
    }

    ChooserPoly ChooserEvaluator::sub_plain(const ChooserPoly &operand, int plain_max_coeff_count, const BigUInt &plain_max_abs_value)
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }
        if (plain_max_coeff_count <= 0)
        {
            throw invalid_argument("plain_max_coeff_count must be positive");
        }
        if (plain_max_abs_value.is_zero())
        {
            return ChooserPoly(operand.max_coeff_count_, operand.max_abs_value_, new SubPlainComputation(*operand.comp_));
        }
        if (operand.max_abs_value_.is_zero())
        {
            return ChooserPoly(plain_max_coeff_count, plain_max_abs_value, new SubPlainComputation(*operand.comp_));
        }

        return ChooserPoly(max(operand.max_coeff_count_, plain_max_coeff_count), operand.max_abs_value_ + plain_max_abs_value, new SubPlainComputation(*operand.comp_));
    }

    ChooserPoly ChooserEvaluator::sub_plain(const ChooserPoly &operand, int plain_max_coeff_count, uint64_t plain_max_abs_value)
    {
        return sub_plain(operand, plain_max_coeff_count, BigUInt(64, plain_max_abs_value));
    }

    ChooserPoly ChooserEvaluator::exponentiate(const ChooserPoly &operand, int exponent)
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }
        if (exponent < 0)
        {
            throw invalid_argument("exponent can not be negative");
        }
        if (exponent == 0 && operand.max_abs_value_.is_zero())
        {
            throw invalid_argument("undefined operation");
        }
        if (exponent == 0)
        {
            return ChooserPoly(1, 1, new ExponentiateComputation(*operand.comp_, exponent));
        }
        if (operand.max_abs_value_.is_zero())
        {
            return ChooserPoly(1, 0, new ExponentiateComputation(*operand.comp_, exponent));
        }

        // There is no known closed formula for the growth factor, but we use the asymptotic approximation
        // k^n * sqrt[6/((k-1)*(k+1)*Pi*n)], where k = max_coeff_count_, n = exponent.
        //uint64_t growth_factor = static_cast<uint64_t>(pow((int)(operand.max_coeff_count_), (int)(exponent)) * sqrt(6 / ((operand.max_coeff_count_ - 1) * (operand.max_coeff_count_ + 1) * 3.1415 * exponent)));
		uint64_t growth_factor = 5;
        int result_bit_count = exponent * operand.max_abs_value_.significant_bit_count() + get_significant_bit_count(growth_factor) + 1;
        int result_uint64_count = divide_round_up(result_bit_count, bits_per_uint64);

        Pointer result_max_abs_value(allocate_uint(result_uint64_count, pool_));

        util::exponentiate_uint(operand.max_abs_value_.pointer(), operand.max_abs_value_.uint64_count(), exponent, result_uint64_count, result_max_abs_value.get(), pool_);

        ConstPointer temp_pointer(duplicate_uint_if_needed(result_max_abs_value.get(), result_uint64_count, result_uint64_count, true, pool_));
        multiply_uint_uint(&growth_factor, 1, temp_pointer.get(), result_uint64_count, result_uint64_count, result_max_abs_value.get());

        return ChooserPoly(exponent * (operand.max_coeff_count_ - 1) + 1, BigUInt(result_bit_count, result_max_abs_value.get()), new ExponentiateComputation(*operand.comp_, exponent));
    }

    ChooserPoly ChooserEvaluator::negate(const ChooserPoly &operand)
    {
        if (operand.max_coeff_count_ <= 0 || operand.comp_ == nullptr)
        {
            throw invalid_argument("operand is not correctly initialized");
        }
        return ChooserPoly(operand.max_coeff_count_, operand.max_abs_value_, new NegateComputation(*operand.comp_));
    }

    ChooserPoly ChooserEvaluator::multiply_many(const vector<ChooserPoly> &operands)
    {
        if (operands.empty())
        {
            throw invalid_argument("operands vector can not be empty");
        }

        int prod_max_coeff_count = 1;
        uint64_t growth_factor = 1;
        int prod_max_abs_value_bit_count = 1;
        vector<Computation*> comps;
        for (vector<ChooserPoly>::size_type i = 0; i < operands.size(); ++i)
        {
            // Throw if any of the operands is not initialized correctly
            if (operands[i].max_coeff_count_ <= 0 || operands[i].comp_ == nullptr)
            {
                throw invalid_argument("input operand is not correctly initialized");
            }

            // Return early if the product is trivially zero
            if (operands[i].max_abs_value_.is_zero())
            {
                return ChooserPoly(1, 0, new MultiplyManyComputation(comps));
            }

            prod_max_coeff_count += operands[i].max_coeff_count_ - 1;
            prod_max_abs_value_bit_count += operands[i].max_abs_value().significant_bit_count();

            growth_factor *= (i == 0 ? 1 : min(operands[i].max_coeff_count_, prod_max_coeff_count));

            comps.push_back(operands[i].comp_);
        }

        prod_max_abs_value_bit_count += get_significant_bit_count(growth_factor);
        int prod_max_abs_value_uint64_count = divide_round_up(prod_max_abs_value_bit_count, bits_per_uint64);

        Pointer prod_max_abs_value(allocate_zero_uint(prod_max_abs_value_uint64_count, pool_));
        *prod_max_abs_value.get() = growth_factor;
        for (vector<ChooserPoly>::size_type i = 0; i < operands.size(); ++i)
        {
            ConstPointer temp_pointer(duplicate_uint_if_needed(prod_max_abs_value.get(), prod_max_abs_value_uint64_count, prod_max_abs_value_uint64_count, true, pool_));
            multiply_uint_uint(temp_pointer.get(), prod_max_abs_value_uint64_count, operands[i].max_abs_value_.pointer(), operands[i].max_abs_value_.uint64_count(), prod_max_abs_value_uint64_count, prod_max_abs_value.get());
        }

        return ChooserPoly(prod_max_coeff_count, BigUInt(prod_max_abs_value_bit_count, prod_max_abs_value.get()), new MultiplyManyComputation(comps));
    }

    bool ChooserEvaluator::select_parameters(const ChooserPoly &operand, EncryptionParameters &destination)
    {
        //return select_parameters(vector<ChooserPoly>{operand}, destination);
		return true;
    }

    bool ChooserEvaluator::select_parameters(const std::vector<ChooserPoly> &operands, EncryptionParameters &destination)
    {
        //return select_parameters(operands, default_noise_standard_deviation_, default_parameter_options_, destination);
		return true;
    }

    bool ChooserEvaluator::select_parameters(const ChooserPoly &operand, double noise_standard_deviation, EncryptionParameters &destination)
    {
       // return select_parameters(vector<ChooserPoly>{operand}, noise_standard_deviation, parameter_options, destination);
		return true;
    }

    bool ChooserEvaluator::select_parameters(const std::vector<ChooserPoly> &operands, double noise_standard_deviation, EncryptionParameters &destination)
    {
        return true;
    }

    Simulation ChooserPoly::simulate(const EncryptionParameters &parms) const
    {
        if (comp_ == nullptr)
        {
            throw logic_error("no operation history to simulate");
        }
        return comp_->simulate(parms);
    }

    void ChooserPoly::reset()
    {
        if (comp_ != nullptr)
        {
            delete comp_;
            comp_ = nullptr;
        }
        max_abs_value_ = BigUInt(1, static_cast<uint64_t>(0));
        max_coeff_count_ = 0;
    }

    void ChooserPoly::set_fresh()
    {
        if (comp_ != nullptr)
        {
            delete comp_;
            comp_ = nullptr;
        }
        comp_ = new FreshComputation();
    }

    ChooserEncoder::ChooserEncoder(uint64_t base) : encoder_(BigUInt(get_significant_bit_count(base), base), base)
    {
    }

    ChooserPoly ChooserEncoder::encode(uint64_t value)
    {
        ChooserPoly chooser_poly;
        encode(value, chooser_poly);
        return chooser_poly;
    }

    void ChooserEncoder::encode(uint64_t value, ChooserPoly &destination)
    {
        BigPoly value_poly = encoder_.encode(value);
        destination.reset();
        destination.max_coeff_count() = value_poly.significant_coeff_count();
        destination.max_abs_value() = poly_infty_norm_coeffmod(value_poly, encoder_.plain_modulus());
    }

    ChooserPoly ChooserEncoder::encode(int64_t value)
    {
        ChooserPoly chooser_poly;
        encode(value, chooser_poly);
        return chooser_poly;
    }

    void ChooserEncoder::encode(int64_t value, ChooserPoly &destination)
    {
        BigPoly value_poly = encoder_.encode(value);
        destination.reset();
        destination.max_coeff_count() = max(value_poly.significant_coeff_count(), 1);
        destination.max_abs_value() = poly_infty_norm_coeffmod(value_poly, encoder_.plain_modulus());
    }

    ChooserPoly ChooserEncoder::encode(BigUInt value)
    {
        ChooserPoly chooser_poly;
        encode(value, chooser_poly);
        return chooser_poly;
    }

    void ChooserEncoder::encode(BigUInt value, ChooserPoly &destination)
    {
        BigPoly value_poly = encoder_.encode(value);
        destination.reset();
        destination.max_coeff_count() = value_poly.significant_coeff_count();
        destination.max_abs_value() = poly_infty_norm_coeffmod(value_poly, encoder_.plain_modulus());
    }

    void ChooserEncryptor::encrypt(const ChooserPoly &plain, ChooserPoly &destination) const
    {
        if (plain.comp_ != nullptr)
        {
            throw invalid_argument("plain has non-null operation history");
        }
        destination = plain;
        destination.set_fresh();
    }

    ChooserPoly ChooserEncryptor::encrypt(const ChooserPoly &plain) const
    {
        ChooserPoly result(plain);
        result.set_fresh();
        return result;
    }

    void ChooserEncryptor::decrypt(const ChooserPoly &encrypted, ChooserPoly &destination) const
    {
        if (encrypted.comp_ == nullptr)
        {
            throw invalid_argument("encrypted has null operation history");
        }
        destination.reset();
        destination.max_abs_value() = encrypted.max_abs_value();
        destination.max_coeff_count() = encrypted.max_coeff_count();
    }

    ChooserPoly ChooserEncryptor::decrypt(const ChooserPoly &encrypted) const
    {
        ChooserPoly result;
        decrypt(encrypted, result);
        return result;
    }
}