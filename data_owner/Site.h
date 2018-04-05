#pragma once
#include "../Eigen/Dense"
#include "../Eigen/Core"
#include "seal.h"
#include <vector>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include "service_provider.h"
using namespace std;
using namespace seal;
class Site
{
public:
	int no_of_features;
	Eigen::MatrixXd X;
	Eigen::MatrixXd Xt;
	Eigen::MatrixXd Y;
	Eigen::MatrixXd Beta;
	Eigen::MatrixXd P;
	Eigen::MatrixXd Xtilde;
	Eigen::MatrixXd Xt_Xtilde;
	Eigen::MatrixXd Xt_Y_P;

	EncryptionParameters parms;
	vector<BigPoly> public_key;

	Site();
	Site(int rows, int cols, BigPoly PK, int ID);
	void updateBeta(double beta[]);
	void updateP();
	void updateXtilde();
	void updateXt_Xtilde();
	void update_Xt_Y_P();
	Eigen::MatrixXd getXtilde();
	Eigen::MatrixXd getXt_Xtilde();
	Eigen::MatrixXd getXt_Y_P();
	vector<vector<BigPoly>> GetEncrptedXt_Xtilde();
	vector<BigPoly> GetEncrptedXt_Y_P();

	~Site();
};

