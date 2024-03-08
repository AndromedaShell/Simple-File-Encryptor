#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <gtk/gtk.h>

#define BUFFER_SIZE 4096
#define FILENAME_LENGTH 8

void handleErrors(void);
void encF(const char *inputFile);
void decF(const char *inputFile);
char *genFN(void);

void encrypt_button_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;

    dialog = gtk_file_chooser_dialog_new("Select a file to encrypt",
                                         GTK_WINDOW(data),
                                         action,
                                         "_Cancel",
                                         GTK_RESPONSE_CANCEL,
                                         "_Open",
                                         GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        char *filename;
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        filename = gtk_file_chooser_get_filename(chooser);
        encF(filename);
        g_free(filename);
    }

    gtk_widget_destroy(dialog);
}

void decrypt_button_clicked(GtkWidget *widget, gpointer data) {
    GtkWidget *dialog;
    GtkFileChooserAction action = GTK_FILE_CHOOSER_ACTION_OPEN;
    gint res;

    dialog = gtk_file_chooser_dialog_new("Select a file to decrypt",
                                         GTK_WINDOW(data),
                                         action,
                                         "_Cancel",
                                         GTK_RESPONSE_CANCEL,
                                         "_Open",
                                         GTK_RESPONSE_ACCEPT,
                                         NULL);

    res = gtk_dialog_run(GTK_DIALOG(dialog));
    if (res == GTK_RESPONSE_ACCEPT) {
        char *filename;
        GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
        filename = gtk_file_chooser_get_filename(chooser);
        decF(filename);
        g_free(filename);
    }

    gtk_widget_destroy(dialog);
}

void handleErrors(void) {
    fprintf(stderr, "An error occurred.\n");
    exit(EXIT_FAILURE);
}

void encF(const char *inputFile) {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        handleErrors();
    }

    char outputFile[1024];
    snprintf(outputFile, sizeof(outputFile), "%s/%s.enc", cwd, genFN());

    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        handleErrors();
    }

    unsigned char key[EVP_MAX_KEY_LENGTH];
    if (!RAND_bytes(key, EVP_MAX_KEY_LENGTH)) {
        handleErrors();
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    if (!RAND_bytes(iv, EVP_MAX_IV_LENGTH)) {
        handleErrors();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handleErrors();
    }

    unsigned char inBuffer[BUFFER_SIZE], outBuffer[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int bytesRead, encryptedLength;

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE, inFile)) > 0) {
        if (EVP_EncryptUpdate(ctx, outBuffer, &encryptedLength, inBuffer, bytesRead) != 1) {
            handleErrors();
        }
        fwrite(outBuffer, 1, encryptedLength, outFile);
    }

    if (EVP_EncryptFinal_ex(ctx, outBuffer, &encryptedLength) != 1) {
        handleErrors();
    }
    fwrite(outBuffer, 1, encryptedLength, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);
}

void decF(const char *inputFile) {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        handleErrors();
    }

    char outputFile[1024];
    snprintf(outputFile, sizeof(outputFile), "%s/%s.txt", cwd, genFN());

    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");
    if (inFile == NULL || outFile == NULL) {
        handleErrors();
    }

    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handleErrors();
    }

    unsigned char inBuffer[BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc())], outBuffer[BUFFER_SIZE];
    int bytesRead, decryptedLength;

    while ((bytesRead = fread(inBuffer, 1, BUFFER_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()), inFile)) > 0) {
        if (EVP_DecryptUpdate(ctx, outBuffer, &decryptedLength, inBuffer, bytesRead) != 1) {
            handleErrors();
        }
        fwrite(outBuffer, 1, decryptedLength, outFile);
    }

    if (EVP_DecryptFinal_ex(ctx, outBuffer, &decryptedLength) != 1) {
        handleErrors();
    }
    fwrite(outBuffer, 1, decryptedLength, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);
}

char *genFN(void) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *randomFilename = malloc(FILENAME_LENGTH + 1);
    if (randomFilename) {
        for (int i = 0; i < FILENAME_LENGTH; ++i) {
            int key = rand() % (sizeof(charset) - 1);
            randomFilename[i] = charset[key];
        }
        randomFilename[FILENAME_LENGTH] = '\0';
    }
    return randomFilename;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "meow");
    gtk_container_set_border_width(GTK_CONTAINER(window), 10);
    gtk_window_set_default_size(GTK_WINDOW(window), 300, 150);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

    GtkWidget *encrypt_button = gtk_button_new_with_label("[+] Encrypt File");
    GtkWidget *decrypt_button = gtk_button_new_with_label("[+] Decrypt File");

    g_signal_connect(encrypt_button, "clicked", G_CALLBACK(encrypt_button_clicked), window);
    g_signal_connect(decrypt_button, "clicked", G_CALLBACK(decrypt_button_clicked), window);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), box);
    gtk_box_pack_start(GTK_BOX(box), encrypt_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), decrypt_button, TRUE, TRUE, 0);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}
