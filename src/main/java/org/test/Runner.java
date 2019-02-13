package org.test;

import java.security.Key;
import java.security.spec.KeySpec;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class Runner implements CommandLineRunner {
	@Value("${intralink.securefilter.secretKey}")
	private String intralinkSecreteKey;

	@Override
	public void run(String... args) throws Exception {
		testJasypt(args);
		testJwt(args);        
	}
	
	private void testJasypt(String... args) throws Exception {
		String secret = "just4Fun";
		String privateData = "topSecret";
		/*
		 * BasicTextEncryptor
		 */

		BasicTextEncryptor encryptor = new BasicTextEncryptor();
		encryptor.setPassword(secret);
		String encryptedText = encryptedText = encryptor.encrypt(privateData);
		String plainText = encryptor.decrypt(encryptedText);
		log.info("password = '{}', encryptedText = '{}', plainText = '{}'", secret, encryptedText, plainText);
		
		/*
		 * One-way encryption 
		 */
		BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
		encryptedText = passwordEncryptor.encryptPassword(privateData);
		log.info("passwords match? {}", passwordEncryptor.checkPassword(privateData, encryptedText));
		
        // Any properties contained in the Spring environment can be detected if they are encrypted
        // following jasypt's property convention. When you retrieve these properties using either
        // environment.getProperty("secret.property") or @Value("${secret.property}"), the decrypted 
        // value is returned. The encrypted property value need to be enclosed by ENC(), such as
        // secret.property=ENC(nrmZtkF7T0kjG/VodDvBw93Ct8EgjCA+).
        
        // Jasypt uses an StringEncryptor to decrypt properties. If no custom StringEncryptor 
        // is found in the Spring Context, one is created automatically that can be configured through 
        // the following properties (System, properties file, command line arguments, environment variable, etc.):
        // The only property required is the encryption password, the rest could be left to use default values.
        // While all this properties could be declared in a properties file, the encryptor password 
        // should not be stored in a property file, it should rather be passed as system property, 
        // command line argument, or environment variable and as far as its name is jasypt.encryptor.password it'll work.
		
		// In this example, property "intralink.securefilter.secretKey" is defined in applicaiton.yml file
		// with value of ENC(2n77OVjxE+ORDF7NWegbOFQylKpmk/lvzWR/Kc8FCj0=). It's injected into field
		// "intralinkSecreteKey" with decrypted value of 9yQdgQJnHhydQF5T.
		log.info("intralinkSecretKey=9yQdgQJnHhydQF5T? {}", intralinkSecreteKey.equals("9yQdgQJnHhydQF5T"));
		
		// The encrypted value using the default StringEncryptor is different every time even when all 
		// the configuration values are the same. The following code demonstrates the encrypted value here
		// is different than that saved in the yml file. However, the decrypted value is the same.

		PooledPBEStringEncryptor stringEncryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPasswordCharArray("cbtbdlrwd".toCharArray());
        config.setAlgorithm("PBEWithMD5AndDES");
        config.setKeyObtentionIterations("1000");
        config.setPoolSize(1);
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setStringOutputType("base64");
        stringEncryptor.setConfig(config);
        
        String text = "9yQdgQJnHhydQF5T";
        String encrypted = stringEncryptor.encrypt(text);
        
        log.info("encrypted = '{}', decrypted = '{}'", encrypted, stringEncryptor.decrypt(encrypted));		
	}

	private void testJwt(String... args) throws Exception {
        
		String CLAIM_CLIENT_TIMEZONE_OFFSET = "clientTimezoneOffset";
		String CLAIM_LANGUAGE = "language";
		String CLAIM_TRANSIT = "transit";
		String CLAIM_OFFICER_ID = "officerId";
		String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxOTcyMDA1Iiwib2ZmaWNlcklkIjoiMTk3MjAwNSIsInRyYW5zaXQiOiIwMDA0MiIsImxhbmd1YWdlIjoiRW5nbGlzaCIsImNsaWVudFRpbWV6b25lT2Zmc2V0IjoiMzAwIiwiaWF0IjoxNTE5MzE0Mzk5LCJuYmYiOjE1MTkzMTQzNjksImV4cCI6MTUxOTMxNDQyOX0.lBjKEk2xRuTFsBYhinsuuKR9UVbJ5GOusCPifHashtE";
		
		// Create the signing key, the algo is AES
		Key signingKey = new SecretKeySpec(intralinkSecreteKey.getBytes(), "AES");
		Jws<Claims> claims = Jwts.parser().setSigningKey(signingKey).parseClaimsJws(tokenString);
		String officerId = claims.getBody().get(CLAIM_OFFICER_ID, String.class);
		String transit = claims.getBody().get(CLAIM_TRANSIT, String.class);
		String language = claims.getBody().get(CLAIM_LANGUAGE, String.class);
		String clientTimezoneOffset = claims.getBody().get(CLAIM_CLIENT_TIMEZONE_OFFSET, String.class);
		Date expiration = claims.getBody().getExpiration(); 
		log.debug("JWT claims: officerId={}, transit={}, language={}, clientTimezoneOffset={}, expiration={}", officerId, transit, language, clientTimezoneOffset, expiration);
	}
}
