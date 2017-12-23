package main

import (
	"github.com/rs/cors"
	"github.com/smolveau/gostreamaes"
	"net/http"
	"path/filepath"
	"strconv"
)

func encryptRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseMultipartForm(32 << 20)

		key := r.FormValue("key")

		file, handler, err := r.FormFile("uploadfile")
		if err != nil {

			panic(err)
		}
		defer file.Close()

		fileLength := handler.Size

		keySize := 16
		aes, err := gostreamaes.NewAESObject(keySize, key)
		if err != nil {
			panic(err)
		}

		encryptedfileName := handler.Filename + ".crypt"
		encryptedfileLength := int(fileLength) + keySize
		w.Header().Set("Content-Disposition", "attachment; filename="+encryptedfileName)
		w.Header().Set("Content-Length", strconv.Itoa(encryptedfileLength))

		err = aes.EncryptStream(file, w)
		if err != nil {
			panic(err)
		}
	}
}

func decryptRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseMultipartForm(32 << 20)

		key := r.FormValue("key")

		file, handler, err := r.FormFile("uploadfile")
		if err != nil {

			panic(err)
		}
		defer file.Close()

		fileLength := handler.Size

		keySize := 16
		aes, err := gostreamaes.NewAESObject(keySize, key)
		if err != nil {
			panic(err)
		}

		encryptedfileName := handler.Filename

		var extension = filepath.Ext(encryptedfileName)
		var newName = encryptedfileName[0 : len(encryptedfileName)-len(extension)]
		encryptedfileLength := int(fileLength) + keySize
		w.Header().Set("Content-Disposition", "attachment; filename="+newName)
		w.Header().Set("Content-Length", strconv.Itoa(encryptedfileLength))

		err = aes.DecryptStream(file, w)
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", encryptRoute)
	mux.HandleFunc("/decrypt", decryptRoute)
	handler := cors.Default().Handler(mux)
	http.ListenAndServe(":9090", handler)
}
