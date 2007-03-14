

int socks_server(int argc, char** argv);
int socks_client(int argc, char** argv);

int main (int argc, char** argv){
	int i;

	for (i=1; i<argc; i++) {
		if(*argv[i]=='-') {
			switch(argv[i][1]) {
				 case 's': 
					 return socks_server(argc,argv);
				 case 'c':
					 return socks_client(argc,argv);
			}
		}
	}
	printf("must specify -s or -c\n");
	return 0;
}

