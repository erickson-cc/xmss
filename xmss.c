#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

static OQS_STATUS do_nothing_save(uint8_t *key_buf, size_t buf_len, void *context) {
	// Função de callback
	(void)(context);
	(void)(buf_len);
	return key_buf != NULL ? OQS_SUCCESS : OQS_ERROR;
}
int main(){
	const char *sigalg = "XMSS-SHA2_10_256";
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(sigalg);

	if (sig == NULL){
		printf("ERRO: Algoritmo não reconhecido\n");
		return 1;
	}

	// Alocação de memória
	uint8_t *public_key = malloc(sig->length_public_key);
	OQS_SIG_STFL_SECRET_KEY *secret_key = OQS_SIG_STFL_SECRET_KEY_new(sigalg);
	if (secret_key == NULL){
		printf("Erro ao alocar a estrutura da chave secreta\n");
		return 1;
	}
	OQS_SIG_STFL_SECRET_KEY_SET_store_cb(secret_key, do_nothing_save, NULL);//Callback
	
	//uint8_t *message = (uint8_t *)"Conteúdo do arquivo protegido.";
	//size_t message_len = strlen((char *)message);
	FILE *file_msg = fopen("mensagem", "rb");
	if (file_msg == NULL) {
		printf("Erro ao abrir o arquivo 'mensagem'.\n");
		return 1;
	}
	fseek(file_msg,0,SEEK_END);
	size_t message_len = ftell(file_msg);
	fseek(file_msg,0,SEEK_SET);
	//Aloca a memória da mensagem
	uint8_t *message = OQS_MEM_malloc(message_len);
	if (message == NULL) {
		printf("Erro ao alocar memória da mensagem\n");
		fclose(file_msg);
		return 1;
	}
	if (fread(message, 1, message_len, file_msg) != message_len) {
		printf("Erro ao ler o arquivo 'mensagem'\n");
		fclose(file_msg);
		OQS_MEM_secure_free(message, message_len);
		return 1;
	}
	printf("Tamanho da mensagem: %zu bytes.\n", message_len);
	fclose(file_msg); // Mensagem recebida com sucesso
	

	uint8_t *signature = malloc(sig->length_signature);
	size_t signature_len;

	// Geração de Chaves
	printf("Gerando chaves...\n");

	if (OQS_SIG_STFL_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
		printf("Erro na geração de chaves\n");
		return 1;
	}

	// Assinatura
	printf("Assinando a mensagem...\n");

	if (OQS_SIG_STFL_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
		printf("Erro na assinatura da mensagem\n");
		OQS_MEM_secure_free(message, message_len);
		return 1;
	}

	FILE *file_sig = fopen("assinatura", "wb");
	if (file_sig == NULL) {
		printf("Erro ao criar o arquivo 'assinatura'.\n");
		return 1;
	}
	fwrite(signature, 1, signature_len, file_sig);
	fclose(file_sig);

	printf("Assinatura gerada com sucesso! Tamanho: %zu bytes\n", signature_len);

	// Verificação da assinatura
	char input;
	printf("Aperte enter para iniciar a verificação da assinatura.\n");
	scanf("%c", &input);

	if (OQS_SIG_STFL_verify(sig, message, message_len, signature, signature_len, public_key) == OQS_SUCCESS){
		printf("A assinatura é válida\n");
	}
	else {
		printf("A assinatura é inválida\n");
	}

	// Limpeza de memória
	
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_secure_free(message, message_len);
	OQS_SIG_STFL_SECRET_KEY_free(secret_key);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_STFL_free(sig);


	return 0;
}
