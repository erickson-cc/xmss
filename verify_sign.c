#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main(int argc, char *argv[]){
	if (argc<=2) {
		fprintf(stderr, "Uso: %s <arquivo_mensagem> <arquivo_assinatura>\n", argv[0]);
		return 1;
	}
	const char *msg_file = argv[1];
	const char *sig_file = argv[2];
	const char *pub_file = "chave_publica.pub";
	const char *sigalg = "XMSS-SHA2_10_256";

	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(sigalg);
	if (sig==NULL) return 1;

	// Leitura da chave_publica.pub
	FILE *f_pub = fopen(pub_file, "rb");
	if (!f_pub) return 1;
	uint8_t *public_key = malloc(sig->length_public_key);
	fread(public_key, 1, sig->length_public_key, f_pub);
	fclose(f_pub);

	// Leitura da mensagem
	FILE *f_msg = fopen(msg_file, "rb");
	if (!f_msg) return 1;
	fseek(f_msg, 0, SEEK_END);
	size_t message_len = ftell(f_msg);
	fseek(f_msg, 0, SEEK_SET);
	uint8_t *message = OQS_MEM_malloc(message_len);
	fread(message, 1, message_len, f_msg);
	fclose(f_msg);

	// Leitura da assinatura
	FILE *f_sig = fopen(sig_file, "rb");
	if (!f_sig) return 1;
	fseek(f_sig, 0, SEEK_END);
	size_t sig_len = ftell(f_sig);
	fseek(f_sig, 0, SEEK_SET);
	uint8_t *signature = malloc(sig_len);
	fread(signature, 1, sig_len, f_sig);
	fclose(f_sig);

	// Verificação
	printf("Verificando a integridade da assinatura...\n");
	if (OQS_SIG_STFL_verify(sig, message, message_len, signature, sig_len, public_key) == OQS_SUCCESS){
		printf("A assinatura é válida\n"); 
	}
	else{
		printf("A assinatura é inválida\n");
	}

	// Limpeza de memória
	free(public_key);
	free(signature);
	OQS_MEM_secure_free(message, message_len);
	OQS_SIG_STFL_free(sig);

	return 0;
}
