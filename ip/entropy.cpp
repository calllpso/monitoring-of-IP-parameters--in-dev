#include <iostream>
#include<fstream>
#include <vector>
#include <cmath>
#include <string>
#include <cstdlib>
#include <ctime>

using namespace std;

char time_buffer[80];
void time_f ();
void entropy(string in0, string out0);


int main()
{

string in1 = "data/prob/IP/ip_vhl.txt";
string in2 = "data/prob/IP/ip_tos.txt";
string in3 = "data/prob/IP/ip_len.txt";
string in4 = "data/prob/IP/ip_id.txt";
string in5 = "data/prob/IP/ip_off.txt";
string in6 = "data/prob/IP/ip_ttl.txt";
string in7 = "data/prob/IP/ip_p.txt";
string in8 = "data/prob/IP/ip_sum.txt";
string in9 = "data/prob/IP/ip_src.txt";
string in10 = "data/prob/IP/ip_dst.txt";

string in11 = "data/prob/TCP/th_sport.txt";
string in12 = "data/prob/TCP/th_dport.txt";
string in13 = "data/prob/TCP/th_seq.txt";
string in14 = "data/prob/TCP/th_ack.txt";
string in15 = "data/prob/TCP/th_offx2.txt";
string in16 = "data/prob/TCP/th_win.txt";
string in17 = "data/prob/TCP/th_sum.txt";
string in18 = "data/prob/TCP/th_urp.txt";

string out1 = "data/entr/IP/entr_ip_vhl.txt";
string out2 = "data/entr/IP/entr_ip_tos.txt";
string out3 = "data/entr/IP/entr_ip_len.txt";
string out4 = "data/entr/IP/entr_ip_id.txt";
string out5 = "data/entr/IP/entr_ip_off.txt";
string out6 = "data/entr/IP/entr_ip_ttl.txt";
string out7 = "data/entr/IP/entr_ip_p.txt";
string out8 = "data/entr/IP/entr_ip_sum.txt";
string out9 = "data/entr/IP/entr_ip_src.txt";
string out10 = "data/entr/IP/entr_ip_dst.txt";

string out11 = "data/entr/TCP/entr_th_sport.txt";
string out12 = "data/entr/TCP/entr_th_dport.txt";
string out13 = "data/entr/TCP/entr_th_seq.txt";
string out14 = "data/entr/TCP/entr_th_ack.txt";
string out15 = "data/entr/TCP/entr_th_offx2.txt";
string out16 = "data/entr/TCP/entr_th_win.txt";
string out17 = "data/entr/TCP/entr_th_sum.txt";
string out18 = "data/entr/TCP/entr_th_urp.txt";


entropy(in1, out1);
entropy(in2, out2);
entropy(in3, out3);
entropy(in4, out4);
entropy(in5, out5);
entropy(in6, out6);
entropy(in7, out7);
entropy(in8, out8);
entropy(in9, out9);
entropy(in10, out10);

entropy(in11, out11);
entropy(in12, out12);
entropy(in13, out13);
entropy(in14, out14);
entropy(in15, out15);
entropy(in16, out16);
entropy(in17, out17);
entropy(in18, out18);

return 0;
}

void time_f ()
{
	time_buffer[80];
	time_t seconds = time(NULL);
	tm* timeinfo = localtime(&seconds);
	char* format = "%d.%m.%Y %H:%M:%S";
	strftime(time_buffer, 80, format, timeinfo);
}

void entropy(string in0, string out0)
{
	ifstream file(in0);
	ofstream fout(out0); 
	float sum=0;
	float H=0;
	vector <float> prob;
	float str;
	int end_str;

	for(int i=0; !file.eof(); i++)
	{
		file >> str;
		if(!isdigit(str))
		{
		end_str = i;	
		prob.push_back(str);
		}
	}

	for(int i=0; i<end_str; i++)
	{ 
		sum = sum + (prob[i]*(log(prob[i])/log(2)));
	}

	H=-sum;
	time_f ();
	
	fout << time_buffer << '\t' << H << endl;
	cout << "H = " << H << endl;
}
