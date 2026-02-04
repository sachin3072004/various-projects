// target.c
#include <stdio.h>
#include <unistd.h>
static int num = 100;
__attribute__((noinline)) int target_add(int a, int b)
{
	for(int i = 0;i< 1000;i++){
		num += i;

	}
    return a + b;
}

int main(void)
{
    int x = 0;

    while (1) {
        int r = target_add(x, x + 1);
        printf("target_add(%d,%d) = %d\n", x, x + 1, r);
        x++;
        sleep(1);
    }
}

