#include "stdafx.h"
#include "Site.h"
#include "service_provider.h"


Site::Site()
{
}

Site::Site(int rows, int cols, BigPoly PK, int ID)
{
	//no_of_features = noOofFeatures;
	string dataPath ; // = "C:\\Users\\sadat\\MyDrive\\FederatedRegression\\Logistic\\SEARCHER\\data_owner\\data\\ucihaberman.txt";
	if (ID == 1)
	{
		//dataPath = "C:\\Users\\sadat\\MyDrive\\FederatedRegression\\Logistic\\SEARCHER\\data_owner\\data\\haberpart1.txt";
		dataPath = "C:\\Users\\sadat\\MyDrive\\FederatedRegression\\Logistic\\SEARCHER\\data_owner\\data\\haberpart1.txt";
	}
	else
	{
		dataPath = "C:\\Users\\sadat\\MyDrive\\FederatedRegression\\Logistic\\SEARCHER\\data_owner\\data\\haberpart2.txt";
	}
	std::ifstream in(dataPath);
	std::string line;

	int nrows = rows; // end - start;
	int ncols = cols;//noOofFeatures + 1;

	this->no_of_features = cols;

	this->X = Eigen::MatrixXd(nrows, ncols);
	this->Y = Eigen::MatrixXd(nrows, 1);
	this->Beta = Eigen::MatrixXd(ncols, 1);
	this->Beta.fill(0);

	if (in.is_open()) {


		cout << "Opened \n";
		for (int row = 0; row < nrows; row++)
			for (int col = 0; col < ncols; col++)
			{
				double item = 0.0;
				in >> item;

				X(row, 0) = 1.0;

				if (col == ncols - 1)
				{
					Y(row, 0) = item*1.0;
				}
				if (col + 1 < ncols)
				{
					X(row, col + 1) = item*1.0;
				}
			}

		in.close();
	}
	else {
		cout << "could not open \n";
	}

	this->P = Eigen::MatrixXd(nrows, 1);
	this->P.fill(0);

	updateP();
	cout << "print pvactoe of DO" << endl;
	cout << this->P << endl;

	this->Xtilde = Eigen::MatrixXd(nrows, ncols);
	this->Xtilde.fill(0);
	updateXtilde();

	this->Xt = this->X.transpose();

	this->Xt_Xtilde = Eigen::MatrixXd(ncols, ncols);
	this->Xt_Xtilde.fill(0);

	//this->Xt_Y_P = Eigen::MatrixXd(ncols, 1);
	//this->Xt_Y_P.fill(0);

	update_Xt_Y_P();
	updateXt_Xtilde();

	

	this->parms.poly_modulus() = "1x^1024 + 1";
	this->parms.coeff_modulus() = ChooserEvaluator::default_parameter_options().at(2048);
	this->parms.plain_modulus() = 1 << 8;

	this->parms.decomposition_bit_count() = 32;

	this->parms.noise_standard_deviation() = ChooserEvaluator::default_noise_standard_deviation();
	this->parms.noise_max_deviation() = 5 * parms.noise_standard_deviation();

	//KeyGenerator generator(parms);
	//generator.generate();

	this->public_key.push_back(PK);//generator.public_key();

}

void Site::updateBeta(double beta[])
{
	for (size_t i = 0; i < this->no_of_features; i++)
	{
		this->Beta(i, 0) = beta[i];

	}
	updateP();
	update_Xt_Y_P();
	updateXtilde();
	updateXt_Xtilde();

}

void Site::updateP()
{
	double z = 0.0;
	double p = 0.0;

	for (int i = 0; i < this->X.rows(); ++i)
	{
		z = 0.0;
		for (int j = 0; j < this->X.cols(); ++j)
		{
			z += this->X(i, j) * this->Beta(j, 0); // b0(1.0) + b1x1 + b2x2 + . . .
		}
		p = 1.0 / (1.0 + exp(-z));  // consider checking for huge value of Math.Exp(-z) here
		this->P(i, 0) = p;
	}
	
}

void Site::updateXtilde()
{
	for (int i = 0; i < this->X.rows(); ++i)
	{
		for (int j = 0; j < this->X.cols(); ++j)
		{
			this->Xtilde(i, j) = this->P(i, 0) * (1.0 - this->P(i, 0)) * this->X(i, j); // note the p(1-p)
		}
	} // i


}


void Site::update_Xt_Y_P()
{
	printf("in update XtYP \n");
	//cout << "Xt " << this->Xt << endl;
	//cout << "Y " << this->Y << endl;
	//cout << "P " << this->P << endl;
	//Eigen::MatrixXd temp(this->Xt.rows(), 1); printf("1 \n");
	//temp = this->Xt * this->Y; printf("2 \n"); 
	//printf("%d %d \n", temp * this->P.rows(), temp * this->P.cols());
	Eigen::MatrixXd temp;
	//temp = this->Xt * this->Y;  printf("2 \n");
	//cout << "temp " << temp << endl;
	temp = this->Y - this->P;
	this->Xt_Y_P = this->Xt * temp; printf("3 \n");
}

Eigen::MatrixXd Site::getXtilde()
{
	return this->Xtilde;
}

void Site::updateXt_Xtilde()
{
	printf("in update Xt_Xtilde\n");
	this->Xt_Xtilde = this->Xt * this->Xtilde;
}

Eigen::MatrixXd Site::getXt_Xtilde()
{
	return this->Xt_Xtilde;
}

Eigen::MatrixXd Site::getXt_Y_P()
{
	return this->Xt_Y_P;
}

vector<vector<BigPoly>> Site::GetEncrptedXt_Xtilde()
{
	printf("in GetEncrptedXt_Xtilde \n");
	BalancedFractionalEncoder encoder(this->parms.plain_modulus(), this->parms.poly_modulus(), 128, 64); printf("1 \n");
	//KeyGenerator generator(parms);
	//generator.generate();
	Encryptor encryptor(this->parms, this->public_key.front()); 

	vector<vector<BigPoly>> Xt_Xtilde_vector;
	vector<BigPoly> row;

	for (size_t i = 0; i < this->Xt_Xtilde.rows(); i++)
	{
		for (size_t j = 0; j < this->Xt_Xtilde.cols(); j++)
		{
			//printf("before encryption \n");
			row.push_back(encryptor.encrypt(encoder.encode(Xt_Xtilde(i, j))));
			//printf("after encryption \n");
		}

		Xt_Xtilde_vector.push_back(row);
		row.clear();

	}

	return Xt_Xtilde_vector;
}

vector<BigPoly> Site::GetEncrptedXt_Y_P()
{
	BalancedFractionalEncoder encoder(this->parms.plain_modulus(), this->parms.poly_modulus(), 128, 64);
	//KeyGenerator generator(parms);
	//generator.generate();
	Encryptor encryptor(this->parms, this->public_key.front());
	vector<BigPoly> Xt_Y_P_vector;

	for (size_t i = 0; i < this->Xt_Y_P.rows(); i++)
	{
		Xt_Y_P_vector.push_back(encryptor.encrypt(encoder.encode(this->Xt_Y_P(i, 0))));
	}

	return Xt_Y_P_vector;
}




Site::~Site()
{
}
