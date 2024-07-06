import javax.crypto.*;
import javax.swing.*;
import java.io.*;
import java.security.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class UserA extends JFrame {
    private JButton encryptButton, signButton, encryptAndSignButton, sendButton, keyPairButton, secretKeyButton, continueButton;
    private JTextArea logArea;
    private JPanel panel = new JPanel();

    public static PublicKey publicKeyA = null;
    private PrivateKey privateKeyA = null;
    private SecretKey secretKey = null;
    private boolean close;

    private byte[] encryptedBytes = null;
    private byte[] encryptedKey = null;
    private byte[] digitalSignature = null;

    public UserA() {
        setTitle("File Encryption & Signature Tool for User A");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        setSize(600, 300);
        int xOffset = 100;
        int yOffset = 200;
        setLocation(xOffset, yOffset);

        encryptButton = new JButton("Encrypt A File");
        signButton = new JButton("Sign File");
        encryptAndSignButton = new JButton("Encrypt And Sign A File");
        sendButton = new JButton("Send To B");
        keyPairButton = new JButton("Generate Key Pair");
        secretKeyButton = new JButton("Generate A Secret Key");
        continueButton = new JButton("Continue");

        logArea = new JTextArea();
        logArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(logArea);

        setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
        add(scrollPane);
        add(panel);
        logArea.setText(" Click the button to generate a new key pair or secret key\n");

        panel.add(keyPairButton);
        panel.add(secretKeyButton);
        panel.add(continueButton);
        continueButton.setEnabled(false);

        // this button generates the new keypair
        keyPairButton.addActionListener(e -> {
            keyPairGenerator();
            keyPairButton.setEnabled(false);
            if(!secretKeyButton.isEnabled()){
                continueButton.setEnabled(true);
            }
        });

        // this button generates the secret key
        secretKeyButton.addActionListener(e -> {
            keyGenerator();
            secretKeyButton.setEnabled(false);
            if(!keyPairButton.isEnabled()){
                continueButton.setEnabled(true);
            }
        });

        // when three button is visible show the text
        Timer timer = new Timer(500, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (encryptButton.isVisible() || signButton.isVisible() || encryptAndSignButton.isVisible()){
                    logArea.setText(" You can choose what you want to do");
                }
            }
        });

        // this button can enable after 3 key generated
        continueButton.addActionListener(e -> {
            clearPanel();
            panel.add(encryptButton);
            panel.add(signButton);
            panel.add(encryptAndSignButton);
            timer.start();
        });

        // user can encrypt or sign (or both) any file from their computer
        // with these 3 buttons (encryptButton, signButton, encryptAndSignButton)

        // option attribute represents the way of encryption
        // because we need to specify our encryption method to receiver

        // if everything clear in encryption process user can send the encrypted file with sendButton

        // sendButton activates the clickButton in receiver panel
        encryptButton.addActionListener(e -> {
            logArea.setText("");
            close = false;
            encryptFile();
            if (!close){
                clearPanel();
                timer.stop();
                panel.add(sendButton);
                UserB.option=0;
            }
        });

        signButton.addActionListener(e -> {
            logArea.setText("");
            close = false;
            signFile();
            if (!close){
                clearPanel();
                timer.stop();
                panel.add(sendButton);
                UserB.option=1;
            }
        });

        encryptAndSignButton.addActionListener(e -> {
            logArea.setText("");
            close = false;
            encryptAndSignFile();
            if (!close){
                timer.stop();
                clearPanel();
                panel.add(sendButton);
                UserB.option=2;
            }
        });

        sendButton.addActionListener(e -> {
            UserB.showClickButton();
            sendButton.setEnabled(false);
            logArea.setText(" File sent successfully ");
            if (encryptedBytes != null ){
                UserB.encryptedBytes= encryptedBytes;
            }
            if (encryptedKey != null ){
                UserB.encryptedKey = encryptedKey;
            }
            if (digitalSignature != null){
                UserB.digitalSignature = digitalSignature;
            }
        });

    }

    // to clear every button in panel when something occurs
    private void clearPanel(){
        panel.removeAll();
        panel.revalidate();
    }

    private void encryptFile() {
        try {
            // open file chooser to make a choice for process
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                FileInputStream fis = new FileInputStream(selectedFile);
                byte[] inputBytes = new byte[(int) selectedFile.length()];
                fis.read(inputBytes);
                fis.close();
                // encrypt the message with secret key. (symmetric encryption)
                try{
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    encryptedBytes =  cipher.doFinal(inputBytes);

                    logArea.setText(" File encrypted successfully.\n");
                }catch (Exception e1){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "The problem might be encryption error\nsecret key error");
                }

                // encrypt secret key by using B' public key. (asymmetric encryption)
                try{
                    Cipher rsaCipher = Cipher.getInstance("RSA");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, UserB.publicKeyB);
                    byte[] encodedSecretKey = secretKey.getEncoded();
                    encryptedKey = rsaCipher.doFinal(encodedSecretKey);

                    logArea.append(" Key encrypted successfully.\n");
                } catch (Exception e2){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "Key encryption error.");
                }
            }else{
                close = true;
                logArea.setText("");
                JOptionPane.showMessageDialog(null, "FILE NOT SELECTED\nTRY AGAIN");
            }
        } catch (Exception ignored) {}
    }

    private void signFile() {
        try {
            // open file chooser to make a choice for process
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {

                File selectedFile = fileChooser.getSelectedFile();
                FileInputStream fis = new FileInputStream(selectedFile);
                byte[] inputBytes = new byte[(int) selectedFile.length()];
                fis.read(inputBytes);
                fis.close();

                try{
                    // encrypt the message with A's private key. (asymmetric encryption)
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, privateKeyA);

                    encryptedBytes= cipher.doFinal(inputBytes);
                }catch (Exception e2){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "The problem might be encryption error\nprivate key error");
                }
                logArea.setText(" File signed successfully.\n");
            }else{
                close = true;
                JOptionPane.showMessageDialog(null, "FILE NOT SELECTED\nTRY AGAIN");
            }
        } catch (Exception ignored) {}
    }

    private void encryptAndSignFile() {
        try {
            JFileChooser fileChooser = new JFileChooser();
            int result = fileChooser.showOpenDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                FileInputStream fis = new FileInputStream(selectedFile);
                byte[] inputBytes = new byte[(int) selectedFile.length()];
                fis.read(inputBytes);
                fis.close();

                try{
                    //get the hash value of the message and encrypt(sign) the hash value
                    // by using A's private key. (asymmetric encryption)
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(inputBytes);
                    Signature signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(privateKeyA);
                    signature.update(hash);
                    digitalSignature = signature.sign();
                    logArea.setText(" File hashed and hash signed successfully\n");

                }catch (Exception e2){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "The problem might be signing hash value");
                }

                try{
                    // encrypt the message with secret key. (symmetric encryption)
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);

                    encryptedBytes  = cipher.doFinal(inputBytes);
                    logArea.append(" File encrypted successfully.\n");
                }catch (Exception e4){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "The problem might be encryption error\nsecret key error");
                }

                try{
                    // encrypt secret key by using B' public key. (asymmetric encryption)
                    Cipher rsaCipher = Cipher.getInstance("RSA");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, UserB.publicKeyB);
                    byte[] encodedSecretKey = secretKey.getEncoded();

                    encryptedKey = rsaCipher.doFinal(encodedSecretKey);
                    logArea.append(" Key encrypted successfully.\n");
                    logArea.append(" File signed and encrypted successfully.\n");
                }catch (Exception e5){
                    close = true;
                    logArea.setText("");
                    JOptionPane.showMessageDialog(null, "Key encryption error.");
                }
            }else{
                close = true;
                logArea.setText("");
                JOptionPane.showMessageDialog(null, "FILE NOT SELECTED\nTRY AGAIN");
            }
        }catch (Exception ignored){}
    }


    private void keyPairGenerator(){
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            publicKeyA = keyPair.getPublic();
            privateKeyA = keyPair.getPrivate();
            logArea.append(" Key pair generated \n");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, " Key pair could not generated");
        }
    }

    private void keyGenerator(){
        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            secretKey = keyGenerator.generateKey();
            logArea.append(" Secret key generated \n");
        }catch (Exception e){
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, " Secret key could not generated");
        }
    }
}
