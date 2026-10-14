#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

static OQS_STATUS save_sk_cb(uint8_t *key_buf, size_t buf_len, void *context) {
	FILE *f = fopen((char*)context,"wb");
	if (f) {
		fwrite(key_buf, 1, buf_len, f);
		fclose(f);
		return OQS_SUCCESS;
	}
	else{
		return OQS_ERROR;
	}
}

int main(){
	const char *sigalg = "XMSS-SHA2_10_256";
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(sigalg);
	if (sig==NULL) return 1;

	// Alocação de memória
	uint8_t *public_key = malloc(sig->length_public_key);
	OQS_SIG_STFL_SECRET_KEY *secret_key = OQS_SIG_STFL_SECRET_KEY_new(sigalg);
	if (!public_key || !secret_key) return 1;
	OQS_SIG_STFL_SECRET_KEY_SET_store_cb(secret_key, save_sk_cb, "chave_secreta.sk");// Callback para o arquivo "chave_secreta.sk"

	printf("Gerando chaves XMSS...\n");
	if (OQS_SIG_STFL_keypair(sig, public_key, secret_key) != OQS_SUCCESS){
		printf("Erro na geração de chaves\n");
		return 1;
	}

	// Chave pública
	FILE *f_pub = fopen("chave_publica.pub", "wb");
	if (f_pub) {
		fwrite(public_key, 1, sig->length_public_key, f_pub);
		fclose(f_pub);
	}

	// Serialização
	uint8_t *sk_buf = NULL;
	size_t sk_buf_len = 0;

	if (OQS_SIG_STFL_SECRET_KEY_serialize(&sk_buf, &sk_buf_len, secret_key) == OQS_SUCCESS) {
		FILE *f_sk = fopen("chave_secreta.sk", "wb");
		if (f_sk) {
			fwrite(sk_buf, 1, sk_buf_len, f_sk);
			fclose(f_sk);
		}
		OQS_MEM_insecure_free(sk_buf);
		printf("Chave serializada em 'chave_secreta.sk'\n");
	}
	else{
		printf("Erro ao serializar a chave secreta\n");
		return 1;
	}

	free(public_key);
	OQS_SIG_STFL_SECRET_KEY_free(secret_key);
	OQS_SIG_STFL_free(sig);

	printf("Sucesso ao gerar as chaves\n");
	return 0;
}
