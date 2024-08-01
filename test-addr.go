package main

import (
	"fmt"
	"net"
	"runtime"
	"io/ioutil"
	"os/user"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/ed25519"
	"crypto/x509"
)

func platform() (string){
	return runtime.GOOS + " " + runtime.GOARCH
}

func uid() (string){

	usr, err := user.Current()

	if err != nil {
		fmt.Printf("Error returning UID: %v", err.Error)
		return "0"
	}
	
	return usr.Uid
}

func localAddresses() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
			continue
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				fmt.Printf("%v : %s (%s)\n", i.Name, v, v.IP.DefaultMask())
				
			case *net.IPNet:
				fmt.Printf("%v : %s [%v/%v]\n", i.Name, v, v.IP, v.Mask)
			}
			
		}
	}
}

func fingerprint() ([32]byte) {
	platform := runtime.GOOS + " " + runtime.GOARCH
	usr, err := user.Current()
	uid := "0"
	output := ""
	
	if err != nil {
		fmt.Printf("Error returning UID: %v\n", err.Error)
	}
	
	uid = usr.Uid

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
	}
	if ifaces != nil {
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			addr := ""
			if err != nil {
				fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
				continue
			}
			for _, a := range addrs {
				switch v := a.(type) {
				case *net.IPAddr:
					addr = fmt.Sprintf("%v : %s (%s)", i.Name, v, v.IP.DefaultMask())
					
				case *net.IPNet:
					addr = fmt.Sprintf("%v : %s [%v/%v]", i.Name, v, v.IP, v.Mask)
				}
				
				output = output + addr
				
			}
		}
	}
	
	return sha256.Sum256([]byte(output + platform + uid))
}

func loadKey(path string) ([]byte){
	privBytes, err := ioutil.ReadFile(path + "key.priv")
	
	if err != nil {
		fmt.Println("No private key found")
		return nil
	}
	
	return privBytes
}

func generateKey(path string) (priv ed25519.PrivateKey, err error){

	var (
		b     []byte
		block *pem.Block
		pub   ed25519.PublicKey
	)

	pub, priv, err = ed25519.GenerateKey(rand.Reader)

	if err != nil {
		fmt.Printf("Generation error : %s", err)
		return nil, err
	}
	
	b, err = x509.MarshalPKCS8PrivateKey(priv)
	
	if err != nil {
		return nil, err
	}

	block = &pem.Block{
		Type:  "SPIRE AGENT PRIVATE KEY",
		Bytes: b,
	}

	fileName := path + "key.priv"
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	if err != nil {
		return nil, err
	}

	// public key
	b, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	block = &pem.Block{
		Type:  "SPIRE AGENT PUBLIC KEY",
		Bytes: b,
	}

	fileName = path + "key.pub"
	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0644)
	return priv, err
}

func sign(data []byte, key ed25519.PrivateKey) ([]byte, error){
	sig, err := key.Sign(nil, data, &ed25519.Options{Context: "SPIRE AGENT NODE ATTESTATION"})

	if err != nil {
		fmt.Printf("Signature failed: %s", err.Error)
		return nil, err
	}

	return sig, nil
}

func main() {
	
	finger := fingerprint() 
	fmt.Printf("fingerprint: %x", finger)
	priv, err := generateKey("./")

	if err != nil {
		fmt.Printf("Error generating key: %s", err.Error)
	}

	if priv != nil {
		signature, err := sign(finger[:], priv)

		if err != nil {
			fmt.Printf("Signature failed for: %s\n", err.Error)
		}
		
		fmt.Printf("Signed fingerprint: %x", signature)
	}
}
