int g[10];
int count;
int fib(int n) { if (n < 2) return n; return fib(n - 1) + fib(n - 2); }
int sum(int a, int b, int c) { return a * 100 + b * 10 + c; }
int main() {
    int i;
    int local[5];
    FILE* f;
    for (i = 0; i < 10; i++) g[i] = i * i;
    for (i = 0; i < 5; i++) local[i] = g[i] + 1;
    printf("fib %d sum %d\n", fib(20), sum(1, 2, 3));
    printf("g9 %d local4 %d count %d\n", g[9], local[4], count++);
    printf("post %d pre %d arr %d\n", count++, ++count, local[2]++);
    printf("neg %d mod %d div %d shr %d shl %d\n", -7 / 2, -7 % 3, 100 / 7, -16 >> 2, 3 << 4);
    printf("[%5d] [%-5d] [%05d] [%x] [%X] [%c] [%s] [%u]\n", 42, 42, 42, 255, 255, 'A', "str", -1);
    printf("cmp %d %d %d %d %d %d\n", 1 < 2, 2 <= 2, 3 > 4, 4 >= 5, 5 == 5, 5 != 5);
    printf("logic %d %d %d %d\n", !0, 3 && 0, 0 || 7, ~5);
    f = fopen("/home/acc_native.txt", "w");
    fprintf(f, "value %d\n", 99);
    fclose(f);
    return fib(10) + local[2];
}
