#ifndef SEAL_EVALUATIONKEYS_H
#define SEAL_EVALUATIONKEYS_H

#include <stdio.h>
#include "bigpoly.h"

namespace seal
{
    /**
    Represents an array of evaluation keys (each represented by a BigPoly) to use during Evaluator operations. The evaluation keys are
    typically initially created by the KeyGenerator for a matching secret key. The evaluation keys may also be saved and loaded from
    a stream with the save() and load() functions.

    While in most cases a user will not need to manipulate the evaluation keys directly, the class provides all of the functionality
    of a BigPoly array. The size of the array (which can be read with count()) is set initially by the constructor and can be resized
    either with the resize() function or with assignment (operator=()). The operator[] indexer functions allow reading/writing
    individual BigPoly's in the array.

    @par Thread Safety
    In general, reading from an EvaluationKeys instance is thread-safe while mutating is not. That is, once a set of EvaluationKeys
    is generated by the KeyGenerator, the same EvaluationKeys instance can be used by several concurrent Evaluator instances as each
    instance only reads from the EvaluationKeys. For more specialized cases where a user may concurrently read and write from an
    EvaluationKeys instance, care must be taken to prevent race conditions. Specifically, the underlying BigPoly array may be freed
    whenever a resize() occurs, the EvaluationKeys instance is destroyed, or an assignment operation occurs, which will invalidate
    the BigPoly references returned by operator[] function. When it is known that a resize will not occur, concurrent reading and
    mutating may still fail when reading/writing the same BigPoly due to the BigPoly's lack of thread safety.

    @see BigPoly for more information about the individual BigPoly's contained in the EvaluationKeys.
    */
    class EvaluationKeys
    {
    public:
        /**
        Creates an empty EvaluationKeys instance with a size of zero. No memory is allocated by this constructor.
        */
        EvaluationKeys();

        /**
        Creates a zero-initialized EvaluationKeys instance with the specified size.

        @param[in] count The number of BigPoly's to allocate space for
        @throws std::invalid_argument if count is negative
        */
        EvaluationKeys(int count);

        /**
        Creates a deep copy of an EvaluationKeys instance. The created EvaluationKeys instance will have the same count and BigPoly
        values as the original.

        @param[in] copy The EvaluationKeys instance to copy from
        */
        EvaluationKeys(const EvaluationKeys &copy);

        /**
        Destroys the EvaluationKeys instance and deallocates the contained array of BigPoly's.
        */
        virtual ~EvaluationKeys();

        /**
        Returns the number of BigPoly's contained in the EvaluationKeys instance.
        */
        int count() const
        {
            return count_;
        }

        /**
        Returns a reference to the BigPoly at the specified index.

        @warning The returned BigPoly is a reference backed by the EvaluationKeys internal array. As such, it is only valid until
        the EvaluationKeys instance is resized or destroyed.
        @throws std::out_of_range If poly_index is not within [0, count())
        */
        const BigPoly &operator[](int poly_index) const;

        /**
        Returns a reference to the BigPoly at the specified index.

        @warning The returned BigPoly is a reference backed by the EvaluationKeys internal array. As such, it is only valid until
        the EvaluationKeys instance is resized or destroyed.
        @throws std::out_of_range If poly_index is not within [0, count())
        */
        BigPoly &operator[](int poly_index);

        /**
        Resizes the EvaluationKeys internal array to store the specified number of BigPoly's, copying over the old BigPoly as much
        as will fit.

        @param[in] count The number of BigPoly's to allocate space for
        @throws std::invalid_argument if count is negative
        */
        void resize(int count);

        /**
        Resets the EvaluationKeys instance to an empty, zero-sized instance. Any space allocated by the EvaluationKeys instance is
        deallocated.
        */
        void clear();

        /**
        Overwrites the EvaluationKeys instance with the BigPolys in the specified EvaluationKeys instance. After assignment, the
        size of EvaluationKeys matches the size of the assigned EvaluationKeys instance.

        @param[in] assign The EvaluationKeys instance to whose value should be assigned to the current EvaluationKeys instance
        */
        EvaluationKeys &operator =(const EvaluationKeys &assign);

        /**
        Saves the EvaluationKeys instance to an output stream. The output is in binary format and not human-readable. The output
        stream must have the "binary" flag set.

        @param[in] stream The stream to save the EvaluationKeys to
        @see load() to load a saved EvaluationKeys instance.
        */
        //void save(std::ostream &stream) const;

        /**
        Loads an EvaluationKeys instance from an input stream overwriting the current EvaluationKeys instance.

        @param[in] stream The stream to load the EvaluationKeys instance from
        @see save() to save an EvaluationKeys instance.
        */
        //void load(std::istream &stream);

    private:
        void reset();

        BigPoly *polys_;

        int count_;
    };
}

#endif // SEAL_EVALUATIONKEYS_H
