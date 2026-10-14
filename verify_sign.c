#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main(int argc, int *argv[]){
	if (argv<=2) {
		fprintf(stderr, "Uso: %s <arquivo_mensagem> <arquivo_assinatura>\n", argv[0]);
		return 1;
	}
	return 0;
}
