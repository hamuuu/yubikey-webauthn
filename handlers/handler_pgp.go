package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func UploadFileHandlerEncrypt(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form to get the file
	err := r.ParseMultipartForm(10 << 20) // Limit file size to 10 MB
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Create a temporary file to save the uploaded content
	tempFilePath := filepath.Join("./tmp", handler.Filename)
	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		http.Error(w, "Error saving the file", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error writing file", http.StatusInternalServerError)
		return
	}

	// Path to store the encrypted file
	encryptedFilePath := tempFilePath + ".gpg"

	// Call GPG to encrypt the file using the YubiKey
	recipient := "7541D3907073FE5F60085B56D5B77BC4E48CF032" // Replace with your recipient key ID
	cmd := exec.Command("gpg", "--output", encryptedFilePath, "--encrypt", "--recipient", recipient, tempFilePath)

	err = cmd.Run()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encrypting file: %v", err), http.StatusInternalServerError)
		return
	}

	// Open the encrypted file to send it back to the client
	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		http.Error(w, "Error opening encrypted file", http.StatusInternalServerError)
		return
	}
	defer encryptedFile.Close()

	// Set the appropriate headers for downloading the file
	w.Header().Set("Content-Disposition", "attachment; filename="+handler.Filename+".gpg")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Transfer-Encoding", "binary")

	// Stream the encrypted file content to the response
	_, err = io.Copy(w, encryptedFile)
	if err != nil {
		http.Error(w, "Error sending file", http.StatusInternalServerError)
		return
	}
}

func UploadFileHandlerDecrypt(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form to get the encrypted file
	err := r.ParseMultipartForm(10 << 20) // Limit file size to 10 MB
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Create a temporary file to save the uploaded encrypted file
	tempFilePath := filepath.Join("./tmp", handler.Filename)
	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		http.Error(w, "Error saving the encrypted file", http.StatusInternalServerError)
		return
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, file)
	if err != nil {
		http.Error(w, "Error writing file", http.StatusInternalServerError)
		return
	}

	// Path to store the decrypted file
	decryptedFilePath := tempFilePath + ".decrypted"

	// Call GPG to decrypt the file using the YubiKey
	cmd := exec.Command("gpg", "--output", decryptedFilePath, "--decrypt", tempFilePath)

	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error decrypting file: %v\nOutput: %s", err, out), http.StatusInternalServerError)
		return
	}

	// Open the decrypted file to send it back to the client
	decryptedFile, err := os.Open(decryptedFilePath)
	if err != nil {
		http.Error(w, "Error opening decrypted file", http.StatusInternalServerError)
		return
	}
	defer decryptedFile.Close()

	// Set the appropriate headers for downloading the file
	w.Header().Set("Content-Disposition", "attachment; filename="+handler.Filename+".decrypted")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Transfer-Encoding", "binary")

	// Stream the decrypted file content to the response
	_, err = io.Copy(w, decryptedFile)
	if err != nil {
		http.Error(w, "Error sending decrypted file", http.StatusInternalServerError)
		return
	}
}
