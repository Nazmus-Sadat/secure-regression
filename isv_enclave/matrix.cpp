
#include "matrix.h"
#include <stdio.h>

#ifndef __QS_MATRIX_CPP
#define __QS_MATRIX_CPP

#include "matrix.h"

// Parameter Constructor                                                                                                                                                      
template<typename T>
QSMatrix<T>::QSMatrix(unsigned _rows, unsigned _cols, const T& _initial) {
	mat.resize(_rows);
	for (unsigned i = 0; i<mat.size(); i++) {
		mat[i].resize(_cols, _initial);
	}
	rows = _rows;
	cols = _cols;
}

// Copy Constructor                                                                                                                                                           
template<typename T>
QSMatrix<T>::QSMatrix(const QSMatrix<T>& rhs) {
	mat = rhs.mat;
	rows = rhs.get_rows();
	cols = rhs.get_cols();
}

// (Virtual) Destructor                                                                                                                                                       
template<typename T>
QSMatrix<T>::~QSMatrix() {}

// Assignment Operator                                                                                                                                                        
template<typename T>
QSMatrix<T>& QSMatrix<T>::operator=(const QSMatrix<T>& rhs) {
	if (&rhs == this)
		return *this;

	unsigned new_rows = rhs.get_rows();
	unsigned new_cols = rhs.get_cols();

	mat.resize(new_rows);
	for (unsigned i = 0; i<mat.size(); i++) {
		mat[i].resize(new_cols);
	}

	for (unsigned i = 0; i<new_rows; i++) {
		for (unsigned j = 0; j<new_cols; j++) {
			mat[i][j] = rhs(i, j);
		}
	}
	rows = new_rows;
	cols = new_cols;

	return *this;
}

// Addition of two matrices                                                                                                                                                   
template<typename T>
QSMatrix<T> QSMatrix<T>::operator+(const QSMatrix<T>& rhs) {
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] + rhs(i, j);
		}
	}

	return result;
}

// Cumulative addition of this matrix and another                                                                                                                             
template<typename T>
QSMatrix<T>& QSMatrix<T>::operator+=(const QSMatrix<T>& rhs) {
	unsigned rows = rhs.get_rows();
	unsigned cols = rhs.get_cols();

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			this->mat[i][j] += rhs(i, j);
		}
	}

	return *this;
}

// Subtraction of this matrix and another                                                                                                                                     
template<typename T>
QSMatrix<T> QSMatrix<T>::operator-(const QSMatrix<T>& rhs) {
	unsigned rows = rhs.get_rows();
	unsigned cols = rhs.get_cols();
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] - rhs(i, j);
		}
	}

	return result;
}

// Cumulative subtraction of this matrix and another                                                                                                                          
template<typename T>
QSMatrix<T>& QSMatrix<T>::operator-=(const QSMatrix<T>& rhs) {
	unsigned rows = rhs.get_rows();
	unsigned cols = rhs.get_cols();

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			this->mat[i][j] -= rhs(i, j);
		}
	}

	return *this;
}

// Left multiplication of this matrix and another                                                                                                                              
template<typename T>
QSMatrix<T> QSMatrix<T>::operator*(const QSMatrix<T>& rhs) {
	printf("in matrix mult \n");

	unsigned RHSrows = rhs.get_rows(); //printf("122 %u %u \n", this->get_rows(), rhs.get_rows());
	unsigned RHScols = rhs.get_cols(); //printf("123 %u %u \n", this->get_cols(), rhs.get_cols());
	QSMatrix result(rows, RHScols, 0.0); //printf("124 \n");
	//printf(" here  \n");

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<RHScols; j++) {
			for (unsigned k = 0; k<RHSrows; k++) {
				//printf(" i j k %d %d %d \n", i, j, k);
				result(i, j) += this->mat[i][k] * rhs(k, j);
			}
		}
	}

	return result;
}

// Cumulative left multiplication of this matrix and another                                                                                                                  
template<typename T>
QSMatrix<T>& QSMatrix<T>::operator*=(const QSMatrix<T>& rhs) {
	QSMatrix result = (*this) * rhs;
	(*this) = result;
	return *this;
}

// Calculate a transpose of this matrix                                                                                                                                       
template<typename T>
QSMatrix<T> QSMatrix<T>::transpose() {
	printf("in matrix transpose \n");
	unsigned trows = this->get_rows();
	unsigned tcols = this->get_cols();
	QSMatrix result(tcols, trows, 0.0); //rows, cols

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(j, i) = this->mat[i][j];
		}
	}
	//rows = tcols;
	//cols = trows;

	printf("out of transpose \n");

	return result;
}

template<typename T>
QSMatrix<T> QSMatrix<T>::inverse() {
	QSMatrix result(rows, cols, 0.0);

	//Container to hold the intermediate results (column size is double)

	QSMatrix container(rows, 2 * cols, 0.0);

	for (int i = 0; i < rows; i++)
	{
		for (int j = 0; j < cols; j++)
		{
			container(i, j) = this->mat[i][j];
			//printf("here %f \n", container(i, j));
		}
	}

	double t;
	for (int i = 0; i<cols; i++)
	{
		for (int j = cols; j<2 * cols; j++)
		{
			if (i == j - cols)
				container(i, j) = 1.0;
			else
				container(i, j) = 0.0;
		}
	}

	for (int i = 0; i<cols; i++)
	{
		//cout << "container is " << container(i, i) << " i is "<< i <<endl;
		//printf("conainer is %f i is %d", container(i, i), i);
		t = container(i, i);
		//cout << "t " << t << endl;
		//printf("t is %f \n", t);
		for (int j = i; j<2 * cols; j++)
			container(i, j) = container(i, j) / t;
		for (int j = 0; j<cols; j++)
		{
			if (i != j)
			{
				t = container(j, i);
				for (int k = 0; k<2 * cols; k++)
					container(j, k) = container(j, k) - t*container(i, k);
			}
		}
	}
	int m;

	for (int i = 0; i<cols; i++)
	{
		for (int j = cols, m = 0; j < 2 * cols, m < cols; j++, m++)
		{
			result(i, m) = container(i, j);
		}

	}

	return result;
}

// Matrix/scalar addition                                                                                                                                                     
template<typename T>
QSMatrix<T> QSMatrix<T>::operator+(const T& rhs) {
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] + rhs;
		}
	}

	return result;
}

// Matrix/scalar subtraction                                                                                                                                                  
template<typename T>
QSMatrix<T> QSMatrix<T>::operator-(const T& rhs) {
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] - rhs;
		}
	}

	return result;
}

// Matrix/scalar multiplication                                                                                                                                               
template<typename T>
QSMatrix<T> QSMatrix<T>::operator*(const T& rhs) {
	printf("in scalar mult \n");
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] * rhs;
		}
	}

	return result;
}

// Matrix/scalar division                                                                                                                                                     
template<typename T>
QSMatrix<T> QSMatrix<T>::operator/(const T& rhs) {
	QSMatrix result(rows, cols, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result(i, j) = this->mat[i][j] / rhs;
		}
	}

	return result;
}

// Multiply a matrix with a vector                                                                                                                                            
template<typename T>
std::vector<T> QSMatrix<T>::operator*(const std::vector<T>& rhs) {
	std::vector<T> result(rhs.size(), 0.0);

	for (unsigned i = 0; i<rows; i++) {
		for (unsigned j = 0; j<cols; j++) {
			result[i] = this->mat[i][j] * rhs[j];
		}
	}

	return result;
}

// Obtain a vector of the diagonal elements                                                                                                                                   
template<typename T>
std::vector<T> QSMatrix<T>::diag_vec() {
	std::vector<T> result(rows, 0.0);

	for (unsigned i = 0; i<rows; i++) {
		result[i] = this->mat[i][i];
	}

	return result;
}

// Access the individual elements                                                                                                                                             
template<typename T>
T& QSMatrix<T>::operator()(const unsigned& row, const unsigned& col) {
	return this->mat[row][col];
}

// Access the individual elements (const)                                                                                                                                     
template<typename T>
const T& QSMatrix<T>::operator()(const unsigned& row, const unsigned& col) const {
	return this->mat[row][col];
}

// Get the number of rows of the matrix                                                                                                                                       
template<typename T>
unsigned QSMatrix<T>::get_rows() const {
	return this->rows;
}

// Get the number of columns of the matrix                                                                                                                                    
template<typename T>
unsigned QSMatrix<T>::get_cols() const {
	return this->cols;
}

#endif