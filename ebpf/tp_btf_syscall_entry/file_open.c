#include <stdio.h>

int main(){
	FILE*fp = fopen("test.txt","r");
	char buf[100];
	while(fgets(buf, 100, fp)){
		printf("Buf %s \n", buf);
	}
	fclose(fp);
}
