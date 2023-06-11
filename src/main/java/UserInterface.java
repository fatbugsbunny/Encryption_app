import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class UserInterface {
    private static Scanner scanner;
    private static final ArrayList<String> passwords = new ArrayList<>();
    private static final ArrayList<byte[]> salts = new ArrayList<>();
    private static final ArrayList<Integer> keyLengths = new ArrayList<>();
    private static int command = 0;
    private static final ArrayList<String> outputFilePaths = new ArrayList<>();
    private static final ArrayList<String> inputFilePaths = new ArrayList<>();

    private static final ArrayList<SecretKey> keys = new ArrayList<>();
    private static final ArrayList<IvParameterSpec> IVs = new ArrayList<>();
    private static boolean usePassword = false;

    public static void start() {
        scanner = new Scanner(System.in);

        // Ask user for the function they'd like to carry out
        getCommand();

        // Retrieve the files
        getFiles();

        // Generate the key
        generateKey();

        // Encrypt or decrypt the files
        encryptOrDecrypt();
    }

    private static void getCommand() {
        System.out.println("--This app uses AES encryption\n");
        System.out.println("What would you like to do? (1 for Encryption - 2 for Decryption)");
        command = Integer.parseInt(scanner.nextLine());
    }

    private static void getFiles() {
        String encryptDecrypt;
        if (command == 1) {
            encryptDecrypt = "encrypt";
        } else encryptDecrypt = "decrypt";

        System.out.println("Would you like to " + encryptDecrypt + " multiple files? (y, n)");
        String answer = scanner.nextLine();

        if (answer.equals("y")) {
            System.out.println("Enter file paths divided by a comma:");
            String[] inputPaths = scanner.nextLine().split(",");
            inputFilePaths.addAll(Arrays.asList(inputPaths));

        } else {
            System.out.println("What is the path of the file you would like to " + encryptDecrypt + ":");
            inputFilePaths.add(scanner.nextLine());

        }
    }
    private static boolean keyOrPassword() {
        if (command == 2) {
            System.out.println("Did you use a password? (y, n)");
        } else {
            System.out.println("Would you like to use a password? (y, n)");
        }

        String answer = scanner.nextLine();
        boolean answerBoolean = false;

        for (int i = 0; i < inputFilePaths.size(); i++) {
            if (answer.equals("y")) {
                usePassword = true;
                answerBoolean = true;
                if (command == 2) {
                    System.out.println("Please type the password you used:");
                    passwords.add(scanner.nextLine());
                    System.out.println("The corresponding salt:");
                    salts.add(Base64.getDecoder().decode(scanner.nextLine()));
                    System.out.println("Corresponding IV:");
                    IVs.add(new IvParameterSpec(Base64.getDecoder().decode(scanner.nextLine())));
                } else {
                    System.out.println("Please type the password:");
                    passwords.add(scanner.nextLine());

                    salts.add(FileEncryption.generateSalt());
                }
            } else {
                if (command == 1) {
                    System.out.println("Select the size of the key: 128, 192, 256");
                    keyLengths.add(Integer.valueOf(scanner.nextLine()));
                }
            }
        }
        return answerBoolean;
    }

    private static void generateKey() {
        // Retrieve key length or password data
        boolean usePassword = keyOrPassword();
        for (int i = 0; i < inputFilePaths.size(); i++) {
            if (command == 2) {
                if (!usePassword) {
                    System.out.println("Enter your key:");
                    String encodedKey = scanner.nextLine();
                    byte[] decodedKey = Base64.getDecoder().decode((encodedKey));
                    keys.add(new SecretKeySpec(decodedKey, "AES"));
                    System.out.println("Corresponding IV:");
                    IVs.add(new IvParameterSpec(Base64.getDecoder().decode(scanner.nextLine())));
                } else {
                    try {
                        keys.add(FileEncryption.getKeyFromPassword(passwords.get(i), salts.get(i)));
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    }
                }
            } else {
                if (!usePassword) {
                    try {
                        keys.add(FileEncryption.generateKey(keyLengths.get(i)));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    try {
                        keys.add(FileEncryption.getKeyFromPassword(passwords.get(i), salts.get(i)));
                    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
    }

    private static void encryptOrDecrypt() {

        boolean flag = true;
        for (int i = 0; i < inputFilePaths.size(); i++) {
            if (command == 1) {
                FileEncryption.generateIv();
                IVs.add(FileEncryption.generateIv());
            }
            try {
                if (command == 1) {
                    outputFilePaths.add(inputFilePaths.get(i).substring(0, inputFilePaths.get(i).lastIndexOf('.')) + ".enc");
                    if (flag) System.out.println("Information to use for decoding in order:");
                    flag = false;

                    if (usePassword) {
                        System.out.println("Salt: " + Base64.getEncoder().encodeToString(salts.get(i)));
                    } else {
                        System.out.println("Key: " + Base64.getEncoder().encodeToString(keys.get(i).getEncoded()));
                    }
                    System.out.println("Iv: " + Base64.getEncoder().encodeToString(IVs.get(i).getIV()));
                } else {
                    System.out.println("Enter the extension of the file before it was encrypted: ");
                    String extension = scanner.nextLine();
                    outputFilePaths.add(inputFilePaths.get(i).substring(0, inputFilePaths.get(i).lastIndexOf('.')) + extension);
                }

                String algorithm = "AES/CBC/PKCS5Padding";
                FileEncryption.encryptOrDecryptFile(algorithm, keys.get(i), IVs.get(i),
                        new File(inputFilePaths.get(i)), new File(outputFilePaths.get(i)), command);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}

