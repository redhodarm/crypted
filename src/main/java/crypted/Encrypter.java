/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypted;

import com.rockaport.alice.Alice;
import com.rockaport.alice.AliceContext;
import com.rockaport.alice.AliceContextBuilder;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 *
 * @author deta
 */
public class Encrypter {
    
    public enum Methods {
        AES_128,
        TRIPLE_DES
    }
    
    public enum Modes {
        ENCRYPT,
        DECRYPT
    }
    
    private Methods method;
    
    private Modes mode;

    public Encrypter() {
    
    }
    
    public void setMethod(Methods method) {
        this.method = method;
    }
    
    public Modes getMode() {
        return mode;
    }
    
    public void setMode(Modes mode) {
        this.mode = mode;
    }
    
    public String run(String plainText, String key) throws GeneralSecurityException, IOException {
        AliceContextBuilder contextBuilder = new AliceContextBuilder();
        decideContextAlgorithm(contextBuilder);
        contextBuilder.setMode(AliceContext.Mode.CTR)
                    .setMacAlgorithm(AliceContext.MacAlgorithm.NONE);
        
        Alice engine = new Alice(contextBuilder.build());
        return runBasedOnMode(engine, plainText, key);
    }
    
    private void decideContextAlgorithm(AliceContextBuilder contextBuilder) {
        if (method == Methods.AES_128) {
            contextBuilder.setAlgorithm(AliceContext.Algorithm.AES)
                   .setKeyLength(AliceContext.KeyLength.BITS_128);
        } else if (method == Methods.TRIPLE_DES) {
            contextBuilder.setAlgorithm(AliceContext.Algorithm.DESede)
                    .setKeyLength(AliceContext.KeyLength.BITS_192)
                    .setIvLength(8);
        }
    }
    
    private String runBasedOnMode(Alice engine, String plainText, String key) throws GeneralSecurityException, IOException {
        byte[] result;
        if (mode == Modes.ENCRYPT) {
            result = engine.encrypt(Base64.getDecoder().decode(plainText), key.toCharArray());
        } else {
            result = engine.decrypt(Base64.getDecoder().decode(plainText), key.toCharArray());
        }
        return Base64.getEncoder().encodeToString(result);
    }
}
