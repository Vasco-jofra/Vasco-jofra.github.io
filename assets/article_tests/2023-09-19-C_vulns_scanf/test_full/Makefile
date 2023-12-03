all:
	gcc -Wall -Wextra -fsanitize=address -o test test.c

codeql:
	codeql database create --language=cpp --command='make' codeql.db