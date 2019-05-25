import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class GenerarClave {
	private String usuario;
	private String password;
	private String semilla;
	private final String texto = "En un lugar de la Mancha,\r\nde cuyo nombre no quiero acordarme";
	private Cipher cifrador;
	private SecretKey key;
	private static Logger logger;
	private static FileHandler fh;
	
	

	/*
	 * Inicio el log
	 */
	private void iniciarLog() {
		logger = Logger.getLogger("PSP07_logger");//creo el logger
		try {
			//creo el fichero de log en la ruta del proyecto carpeta doc (refrescar para ver tras ejecución)
			String rutaLog = new File(".").getCanonicalPath() + File.separator +"doc"+
					File.separator + "PSP07_log.txt";
			File log = new File(rutaLog); 
			if(!log.exists() &&  !log.createNewFile()) {
				System.out.println("no se ha podido crear el log");
			}
			
			fh = new FileHandler(rutaLog, true);//inicializo el fileHandler
			SimpleFormatter formatter = new SimpleFormatter();//doy formato de salida
			fh.setFormatter(formatter);
			logger.addHandler(fh);
			logger.setUseParentHandlers(true); //  visualizar por pantalla
			logger.setLevel(Level.ALL);// guardar todos los avisos
			logger.log(Level.INFO, new Date() + " | Programa iniciado");			
		} catch (SecurityException | IOException e) {
			logger.log(Level.WARNING, e.getMessage());			
		}
	}
	
	
	/*
	 * Método para pedir el usuario y la contraseña al usuario
	 */
	@SuppressWarnings("resource")
	private void pedirDatosUsuario() {	
		logger.log(Level.INFO, new Date() + " | Pidiendo datos usuario");	
		Scanner sc = new Scanner(System.in);

		//pido el nombre de usuario mientras no introduzca datos
		while (usuario == null || usuario.isEmpty()) { 
			System.out.println("Introduzca su usuario");
			usuario = sc.nextLine();
		}

		//pido una contraseña de mínimo 8 caracteres
		while (password == null || password.isEmpty() || password.length() < 8) {
			System.out.println("Introduzca su password. Mínimo 8 caracteres");
			password = sc.nextLine();
		}
		//genero la semilla con el usuario y contraseña
		semilla = usuario + password;
			
	}

	/*
	 * Método para generar la pareja de claves
	 */
	private void generarParejaClaves() {
		logger.log(Level.INFO, new Date() + " | Generando pareja de claves");	
		KeyGenerator kg = null;
		
		//configuro el keyGenerator
		try {
			kg = KeyGenerator.getInstance("AES");			
			//A partir de un número aleatorio con semilla la cadena del nombre de usuario + password
			//Clase java.security.SecureRandom produce números aleatorios de calidad
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(semilla.getBytes());//asigno la semilla al objeto secureRandom
			kg.init(128,secureRandom);//clave de longitud 128 bits
			logger.log(Level.INFO, new Date() +" pareja de claves generada" );
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, e.getMessage());
		}
		
		key = kg.generateKey(); //genero la clave

		try {
			cifrador = Cipher.getInstance("Rijndael/ECB/PKCS5Padding"); //objeto Cipher con la especificación del enunciado			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			logger.log(Level.SEVERE, new Date() +" | "+ e1.getMessage());
			System.exit(1);
		}

		try {
			//inicializo el cipher con la clave
			cifrador.init(Cipher.ENCRYPT_MODE, key);
		} catch (InvalidKeyException e) {
			logger.log(Level.SEVERE, new Date() +" | "+ e.getMessage());
			e.printStackTrace();
		}

	}

	
	/*
	 * Método para guardar el fichero de texto encriptado
	 */
	private void guardarTextoFicheroEncriptado() { // fichero encriptado de salida
		logger.log(Level.INFO, new Date() +" | Guardando fichero encriptado");
		FileOutputStream fos = null;
		try {
			//escribo en el fichero.cifrado el texto encriptado
			fos = new FileOutputStream("fichero.cifrado");
			fos.write(cifrador.doFinal(texto.getBytes()));
		} catch (IOException | IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.WARNING, e.getMessage());//guardo en el log posibles excepciones
		} finally {
			if (fos != null) { //si es distinto de null  cierro el fileoutputstream
				try {
					fos.close();
				} catch (IOException e) {
					logger.log(Level.SEVERE, e.getMessage());
				}
			}
		}

	}

	/*
	 * Desencripto el fichero cifrado
	 */
	private void desencriptar() {
		logger.log(Level.INFO, new Date() + " | Desencriptando fichero");
		
		Path ruta = Paths.get("fichero.cifrado"); //ruta del fichero.cifrado 
		byte[] bufferCifrado; //array para almacenar el fichero
		try {
			bufferCifrado = Files.readAllBytes(ruta); //leo el fichero
			cifrador.init(Cipher.DECRYPT_MODE, key); //cambio el objeto cipher para que desencripte
			
			System.out.println(
					"Texto desencriptado \n------------------------------------------\n" 
			+ new String(cifrador.doFinal(bufferCifrado))
					+"\n------------------------------------------\n");
		} catch (IOException | IllegalBlockSizeException | BadPaddingException |InvalidKeyException  e1) {
			logger.log(Level.WARNING, e1.getMessage());
		} 

	}

	
	/*
	 *Cerrar el log
	 */
	private void cerrarLog() {		
		logger.log(Level.INFO, new Date() + " | app finalizada  " );
		fh.close();
		logger.removeHandler(fh);
	}
	
	
	public static void main(String[] args) {
		//creación del objeto y llamadas a las métodos
		GenerarClave generarClave = new GenerarClave();
		generarClave.iniciarLog();
		generarClave.pedirDatosUsuario();
		generarClave.generarParejaClaves();
		generarClave.guardarTextoFicheroEncriptado();
		generarClave.desencriptar();
		generarClave.cerrarLog();

	}

}
