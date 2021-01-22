#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <stdio.h>
#include<fstream>

using namespace std;

void sort(string in0, string out0);
 
int main()
{
//par
string in1 = "data/par/IP/ip_vhl.txt";
string in2 = "data/par/IP/ip_tos.txt";
string in3 = "data/par/IP/ip_len.txt";
string in4 = "data/par/IP/ip_id.txt";
string in5 = "data/par/IP/ip_off.txt";
string in6 = "data/par/IP/ip_ttl.txt";
string in7 = "data/par/IP/ip_p.txt";
string in8 = "data/par/IP/ip_sum.txt";
string in9 = "data/par/IP/ip_src.txt";
string in10 = "data/par/IP/ip_dst.txt";

string in11 = "data/par/TCP/th_sport.txt";
string in12 = "data/par/TCP/th_dport.txt";
string in13 = "data/par/TCP/th_seq.txt";
string in14 = "data/par/TCP/th_ack.txt";
string in15 = "data/par/TCP/th_offx2.txt";
string in16 = "data/par/TCP/th_win.txt";
string in17 = "data/par/TCP/th_sum.txt";
string in18 = "data/par/TCP/th_urp.txt";

//prob
string out1 = "data/prob/IP/ip_vhl.txt";
string out2 = "data/prob/IP/ip_tos.txt";
string out3 = "data/prob/IP/ip_len.txt";
string out4 = "data/prob/IP/ip_id.txt";
string out5 = "data/prob/IP/ip_off.txt";
string out6 = "data/prob/IP/ip_ttl.txt";
string out7 = "data/prob/IP/ip_p.txt";
string out8 = "data/prob/IP/ip_sum.txt";
string out9 = "data/prob/IP/ip_src.txt";
string out10 = "data/prob/IP/ip_dst.txt";

string out11 = "data/prob/TCP/th_sport.txt";
string out12 = "data/prob/TCP/th_dport.txt";
string out13 = "data/prob/TCP/th_seq.txt";
string out14 = "data/prob/TCP/th_ack.txt";
string out15 = "data/prob/TCP/th_offx2.txt";
string out16 = "data/prob/TCP/th_win.txt";
string out17 = "data/prob/TCP/th_sum.txt";
string out18 = "data/prob/TCP/th_urp.txt";

//sort
sort(in1, out1);
sort(in2, out2);
sort(in3, out3);
sort(in4, out4);
sort(in5, out5);
sort(in6, out6);
sort(in7, out7);
sort(in8, out8);
sort(in9, out9);
sort(in10, out10);

sort(in11, out11);
sort(in12, out12);
sort(in13, out13);
sort(in14, out14);
sort(in15, out15);
sort(in16, out16);
sort(in17, out17);
sort(in18, out18);

return 0;
}


void sort(string in0, string out0)
{
	ifstream file(in0);
	vector <string> name;
	vector <int> repeat;
	vector <float> prob;
	string str;
	int end_str = 0;
	int count_str = 0;
	int value;
	for(int i=0; !file.eof(); i++)
	{
		getline(file, str);

		if(str == "") 
		{
			continue;
		}	
		
		name.push_back(str);	
		end_str = i+1;
	}
	value = end_str;


	for(int i=0; i<end_str; i++)
	{
		repeat.push_back(1);
		int temp=0;
		for(int j=i; j<end_str-1; j++)	
		{
			
			if(name[i] == name[j+1])
			{
				repeat[i]++;
				
				name.erase(name.begin() + j+1);
				end_str--;
				j--;
			}
			else if((temp==0) && (name[i] != name[j+1]))
			{
				i=j;
				temp++;
			}	
		}
	}

	for(int i=0; i<end_str; i++)
	{
		float a = repeat[i];
		float res = a/value;
		prob.push_back(res);
	}

	ofstream fout(out0); 
	for(int i=0; i<end_str; i++)
	{
		fout << prob[i] << '\n';
	}
	fout.close();
	
/*
	FILE* repeat_file;
	////
	
	
	repeat_file = fopen(name2, "w");

	for(int i=0; i<end_str; i++)
	{
		fprintf(repeat_file,"%f\n", prob[i]);
	}
	fclose(repeat_file);
*/
}
