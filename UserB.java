import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.*;
import java.nio.charset.StandardCharsets;


public class UserB extends JFrame {
    private static JButton click,openButton,keyPairButton,downloadButton;
    private static JTextArea logArea;
    private static JPanel panel = new JPanel();

    public static int option;
    public static PublicKey publicKeyB = null;
    private PrivateKey privateKeyB = null;
    private boolean verified;

    public static byte[] encryptedBytes = null;
    public static byte[] encryptedKey = null;
    public static byte[] digitalSignature = null;
    private byte[] decryptedBytes = null;


    public UserB() {
        setTitle("File Encryption & Signature Tool for User B");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setSize(600, 300);
        int xOffset = 750;
        int yOffset = 200;
        setLocation(xOffset, yOffset);

        click = new JButton("<>");
        openButton = new JButton("Open File");
        keyPairButton = new JButton("Generate key pair");
        downloadButton = new JButton("Download file");

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
        add(scrollPane);
        add(panel);
        logArea.setText(" Click the button to generate a new key pair\n");

        panel.add(keyPairButton);

        // this button generates the new keypair
        keyPairButton.addActionListener(e -> {
            keyPairGenerator();
            logArea.setText(" Please wait until something sent");
            panel.removeAll();
            panel.setVisible(false);
        });

        // this button become visible after something send from A
        // and it applies the decryption
        click.addActionListener(e -> {
            logArea.setText("");
            panel.removeAll();
            panel.revalidate();
            if (option==0){
                decryptFile();
                logArea.setText(" WARNING!!\n It seems that User A has sent a file, but we don't make sure it sent from A. " +
                        "\n Press the 'Open File' button to view the file. ");
                panel.add(openButton);
            }else if (option==1){
                verifySignature();
                logArea.setText(" User A sent a signed file.\n" +
                        " Press the 'Open File' button to view the file.");
                panel.add(openButton);
            }else if (option==2){
                verified = false;
                decryptSignedFile();
                if (verified) {
                    logArea.setText(" User A sent signed file and file sent in a secure way\n");
                    panel.add(openButton);
                } else {
                    logArea.setText(" User A sent not signed file and file sent in a secure way\n");
                }
            }
        });

        // it shows the text of the decrypted message
        openButton.addActionListener(e -> {
            logArea.setText(new String(decryptedBytes, StandardCharsets.UTF_8));
            panel.removeAll();
            panel.revalidate();
            panel.add(downloadButton);
        });

        // massage can download as a txt file with this button
        downloadButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showSaveDialog(null); // Hedef dosya yolu seçimi için dialog aç
            if (result == JFileChooser.APPROVE_OPTION) {
                try {
                    FileOutputStream fos = new FileOutputStream("decrypted_file.txt");
                    fos.write(decryptedBytes);
                    Path sourcePath = Paths.get("decrypted_file.txt");
                    Path destinationPath = fileChooser.getSelectedFile().toPath();
                    Files.copy(sourcePath, destinationPath);
                    JOptionPane.showMessageDialog(null, "File downloaded succesfully.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error " + ex.getMessage());
                }
            }
            downloadButton.setEnabled(false);
        });
    }

    // this method can only trigger by A
    public static void showClickButton(){
        panel.setVisible(true);
        panel.removeAll();
        panel.revalidate();
        panel.add(click);

    }

    private void decryptFile() {

        try {
            // decryption for symmetric key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKeyB);

            byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);

            try{
                // decryption for message by using symmetric key
                SecretKey secretKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE,secretKey);

                decryptedBytes = cipher.doFinal(encryptedBytes);
            }catch (Exception e1){
                JOptionPane.showMessageDialog(null, "ERROR!\nThe problem might be decryption error\nsecret key error");
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "ERROR!\nThe problem might be private key error");
        }
    }

    private void verifySignature(){
        try {
            // decrypt by using A's public key because encrypted by A's private key
            // it proves that message encrypted only by A
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, UserA.publicKeyA);

            decryptedBytes = cipher.doFinal(encryptedBytes);
        }catch (Exception e){
            logArea.setText(e.getMessage()+ "\n The problem might be key error ");
        }
    }

    private void decryptSignedFile() {
        // decrypt file with  decryptFile() method to fill decryptedBytes
        decryptFile();
        try {
            // sign the decryptedBytes (it means that get hash and sign the hash)
            // compare the signatures which is sent and which is created from decryptedBytes
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(decryptedBytes);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(UserA.publicKeyA);
            sig.update(hash);

            // if the signatures are same set the verified as true
            verified = sig.verify(digitalSignature);
        }catch (Exception e){
            JOptionPane.showMessageDialog(null, "The problem might be hash error");
        }
    }

    private void keyPairGenerator(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            publicKeyB = keyPair.getPublic();
            privateKeyB = keyPair.getPrivate();
            logArea.append(" key pair generated \n");
        } catch (NoSuchAlgorithmException e) {
            JOptionPane.showMessageDialog(null, " Key pair could not generated");
        }
    }
}


