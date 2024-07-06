import javax.swing.*;

public class Main {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new UserA().setVisible(true);
            new UserB().setVisible(true);
        });
    }
}
