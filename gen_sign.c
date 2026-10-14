#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

static OQS_STATUS save_sk_cb(uint8_t *key_buf, size_t buf_len, void *context){
	FILE *f = fopen((char *)context, "wb");
	if (f) {
		fwrite(key_buf, 1, buf_len, f);
		fclose(f);
		return OQS_SUCCESS;
	}
	return OQS_ERROR;
}

int main(int argc, char *argv[]){
	const char *msg_file = (argc>=2) ? argv[1] : "mensagem";
	const char *sigalg = "XMSS-SHA2_10_256";
	
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(sigalg);
	if(sig==NULL) return 1;
	
	// Leitura do arquivo da mensagem
	FILE *file_msg = fopen(msg_file, "rb");
	if(file_msg==NULL) return 1;
	fseek(file_msg,0,SEEK_END);
	size_t message_len = ftell(file_msg);
	fseek(file_msg,0,SEEK_SET);
	// Alocação de memória
	uint8_t *message = OQS_MEM_malloc(message_len);
	fread(message, 1, message_len, file_msg);
	fclose(file_msg);

	// Leitura da Chave secreta
	FILE *f_sk = fopen("chave_secreta.sk", "rb");
	if (!f_sk) return 1;
	fseek(f_sk, 0, SEEK_END);
	size_t sk_len = ftell(f_sk);
	fseek(f_sk, 0, SEEK_SET);
	uint8_t *sk_buf = malloc(sk_len);
	fread(sk_buf, 1, sk_len, f_sk);
	fclose(f_sk);

	// Injeção de estado
	OQS_SIG_STFL_SECRET_KEY *secret_key = OQS_SIG_STFL_SECRET_KEY_new(sigalg);
	
	// Registra Callback
	OQS_SIG_STFL_SECRET_KEY_SET_store_cb(secret_key, save_sk_cb, "chave_secreta.sk");

	// Geração da assinatura
	uint8_t *signature = malloc(sig->length_signature);
	size_t signature_len;
	printf("Assinando o arquivo %s...\n", msg_file);

	if (OQS_SIG_STFL_sign(sig, signature, &signature_len, message, message_len, secret_key) == OQS_SUCCESS) {
		FILE *file_sig = fopen("assinatura", "wb");
		if (file_sig) {
			fwrite(signature, 1, signature_len, file_sig);
			fclose(file_sig);
			printf("Assinatura gerada e salva em 'assinatura' (%zu bytes).\n", signature_len);
		}
	}

	free(sk_buf);
	free(signature);
	OQS_MEM_secure_free(message, message_len);
	OQS_SIG_STFL_SECRET_KEY_free(secret_key);
	OQS_SIG_STFL_free(sig);
	return 0;
}
