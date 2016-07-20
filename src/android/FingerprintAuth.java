package com.cordova.plugin.android.fingerprintauth;

import org.apache.cordova.CordovaWebView;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@TargetApi(23)
public class FingerprintAuth extends CordovaPlugin {

	public static final String TAG = "FingerprintAuth";
	public static String packageName;

	private static final String DIALOG_FRAGMENT_TAG = "FpAuthDialog";
	private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
	private static final String PESAMAX_KEY_STORE_ALIAS = "PesamaxFingerprintStore";


	KeyguardManager mKeyguardManager;
	FingerprintAuthenticationDialogFragment mFragment;
	public static KeyStore mKeyStore;
	public static KeyGenerator mKeyGenerator;
	public static Cipher mCipher;
	public static Context context;
	private FingerprintManager mFingerPrintManager;

	public static CallbackContext mCallbackContext;
	public static PluginResult mPluginResult;

	/** Alias for our key in the Android Key Store */
	private static String mClientId;
	/** Used to encrypt token */
	private static String mClientSecret;

	/**
	 * Constructor.
	 */
	public FingerprintAuth() {
	}

	/**
	 * Sets the context of the Command. This can then be used to do things like
	 * get file paths associated with the Activity.
	 *
	 * @param cordova
	 *            The context of the main Activity.
	 * @param webView
	 *            The CordovaWebView Cordova is running in.
	 */

	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
		super.initialize(cordova, webView);
		Log.v(TAG, "Init FingerprintAuth");
		packageName = cordova.getActivity().getApplicationContext().getPackageName();
		context = cordova.getActivity().getApplicationContext();
		mPluginResult = new PluginResult(PluginResult.Status.NO_RESULT);

		if (android.os.Build.VERSION.SDK_INT < 23) {
			return;
		}

		mKeyguardManager = cordova.getActivity().getSystemService(KeyguardManager.class);
		mFingerPrintManager = cordova.getActivity().getApplicationContext()
				.getSystemService(FingerprintManager.class);

		try {
			mKeyGenerator = KeyGenerator.getInstance(
					KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
			mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
		} catch (KeyStoreException e) {
			throw new RuntimeException("Failed to get an instance of KeyStore", e);
		}

		try {
			mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
					+ KeyProperties.BLOCK_MODE_CBC + "/"
					+ KeyProperties.ENCRYPTION_PADDING_PKCS7);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Failed to get an instance of Cipher", e);
		} catch (NoSuchPaddingException e) {
			throw new RuntimeException("Failed to get an instance of Cipher", e);
		}
	}

	/**
	 * Executes the request and returns PluginResult.
	 *
	 * @param action            The action to execute.
	 * @param args              JSONArry of arguments for the plugin.
	 * @param callbackContext   The callback id used when calling back into JavaScript.
	 * @return                  A PluginResult object with a status and message.
	 */
	public boolean execute(final String action,
						   JSONArray args,
						   CallbackContext callbackContext) throws JSONException {
		mCallbackContext = callbackContext;
		//Log.v(TAG, "FingerprintAuth action: " + action);

		JSONObject arg_object = args.getJSONObject(0);
		if (action.equals("checkpin")) {
			JSONObject resultJson = new JSONObject();
			if(!POkey.isEntryAvailable(PESAMAX_KEY_STORE_ALIAS)){
				//POkey.createKeyPair(cordova.getActivity().getApplicationContext(),PESAMAX_KEY_STORE);
				resultJson.put("PesamaxKeystore", "Pesamax Fingerprint keystore does not exist");
				resultJson.put("status", false);
			}else {
				resultJson.put("PesamaxKeystore", "Pesamax Fingerprint keystore  exist");
				resultJson.put("status", true);
			}
			//resultJson.put("PesamaxKeystore", "Pesamax Fingerprint keystore  exist");
			mPluginResult = new PluginResult(PluginResult.Status.OK);
			mCallbackContext.success(resultJson);
			mCallbackContext.sendPluginResult(mPluginResult);
			return true;
		}

		if (action.equals("getuser")) {
			JSONObject resultJson = new JSONObject();
			if (!arg_object.has("user_data")) {
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("Missing User");
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}
			String user_id = arg_object.getString("user_data");
			try {
				byte[] user = POkey.decrypt(Base64.decode(user_id, Base64.DEFAULT), PESAMAX_KEY_STORE_ALIAS);
				resultJson.put("user_id", new String(user));
				mPluginResult = new PluginResult(PluginResult.Status.OK);
				mCallbackContext.success(resultJson);
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}catch (Exception e){
				return setPluginResultError("Failed to get user");
			}
		}

		if (action.equals("setpin")) {
			JSONObject resultJson = new JSONObject();
			if (!arg_object.has("pin")) {
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("Missing Pin Parameters to set up fingerrpint login");
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}

			if(!POkey.isEntryAvailable(PESAMAX_KEY_STORE_ALIAS)) {
				try{
					POkey.createKeyPair(cordova.getActivity().getApplicationContext(),PESAMAX_KEY_STORE_ALIAS);
					//return setPluginResultError("Build succcessfully ");
				}catch (NoSuchAlgorithmException e) {
					return setPluginResultError("NoSuchAlgorithmException");
				}catch (NoSuchProviderException e) {
					return setPluginResultError("NoSuchProviderException");
				}catch (NullPointerException e) {

					return setPluginResultError("NullPointerException"+e);
				} catch (IllegalArgumentException e) {
					return setPluginResultError("IllegalArgumentException");
				}catch (Exception e){
					return setPluginResultError("Failed to Create key");

				}

			}
			String Pin = arg_object.getString("pin");
			try{
				byte[] pin_encrypted = POkey.encrypt(Pin.getBytes(), PESAMAX_KEY_STORE_ALIAS);
				resultJson.put("encrypted",POkey.BytestoString(pin_encrypted));
				mPluginResult = new PluginResult(PluginResult.Status.OK);
				mCallbackContext.success(resultJson);
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}catch (Exception e){
				return setPluginResultError("Failed to encrpty");

			}

		}


		if (action.equals("authenticate")) {
			if (android.os.Build.VERSION.SDK_INT < 23) {
				Log.e(TAG, "minimum SDK version 23 required");
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("minimum SDK version 23 required");
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}

			if (!arg_object.has("clientId") || !arg_object.has("clientSecret")) {
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("Missing required parameters");
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}
			mClientId = arg_object.getString("clientId");
			mClientSecret = arg_object.getString("clientSecret");
			if (isFingerprintAuthAvailable()) {
				createKey();
				cordova.getActivity().runOnUiThread(new Runnable() {
					public void run() {
						// Set up the crypto object for later. The object will be authenticated by use
						// of the fingerprint.
						if (initCipher()) {

							mFragment = new FingerprintAuthenticationDialogFragment();
							mFragment.setCancelable(false);
							// Show the fingerprint dialog. The user has the option to use the fingerprint with
							// crypto, or you can fall back to using a server-side verified password.
							mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
							mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
						} else {
							// This happens if the lock screen has been disabled or or a fingerprint got
							// enrolled. Thus show the dialog to authenticate with their password first
							// and ask the user if they want to authenticate with fingerprints in the
							// future
							mFragment.setCryptoObject(new FingerprintManager.CryptoObject(mCipher));
							mFragment.setStage(
									FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
							mFragment.show(cordova.getActivity().getFragmentManager(), DIALOG_FRAGMENT_TAG);
						}
					}
				});
				mPluginResult.setKeepCallback(true);
				mCallbackContext.sendPluginResult(mPluginResult);

			} else {
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("Fingerprint authentication not available");
				mCallbackContext.sendPluginResult(mPluginResult);
			}
			return true;
		} else if (action.equals("availability")) {
			if (android.os.Build.VERSION.SDK_INT < 23) {
				Log.e(TAG, "minimum SDK version 23 required");
				mPluginResult = new PluginResult(PluginResult.Status.ERROR);
				mCallbackContext.error("minimum SDK version 23 required");
				mCallbackContext.sendPluginResult(mPluginResult);
				return true;
			}

			JSONObject resultJson = new JSONObject();
			resultJson.put("isAvailable", isFingerprintAuthAvailable());
			resultJson.put("isHardwareDetected", mFingerPrintManager.isHardwareDetected());
			resultJson.put("hasEnrolledFingerprints", mFingerPrintManager.hasEnrolledFingerprints());
			mPluginResult = new PluginResult(PluginResult.Status.OK);
			mCallbackContext.success(resultJson);
			mCallbackContext.sendPluginResult(mPluginResult);
			return true;
		}
		return false;
	}

	private boolean isFingerprintAuthAvailable() {
		return mFingerPrintManager.isHardwareDetected()
				&& mFingerPrintManager.hasEnrolledFingerprints();
	}


	/**
	 * Initialize the {@link Cipher} instance with the created key in the {@link #createKey()}
	 * method.
	 *
	 * @return {@code true} if initialization is successful, {@code false} if the lock screen has
	 * been disabled or reset after the key was generated, or if a fingerprint got enrolled after
	 * the key was generated.
	 */
	private boolean initCipher() {
		try {
			mKeyStore.load(null);
			SecretKey key = (SecretKey) mKeyStore.getKey(mClientId, null);
			mCipher.init(Cipher.ENCRYPT_MODE, key);
			return true;
		} catch (KeyStoreException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("KeyStoreException");
		} catch (CertificateException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("CertificateException");
		} catch (UnrecoverableKeyException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("UnrecoverableKeyException");
		} catch (IOException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("IOException");
		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("NoSuchAlgorithmException");
		} catch (InvalidKeyException e) {
//			throw new RuntimeException("Failed to init Cipher", e);
			return setPluginResultError("InvalidKeyException");
		} catch (Exception e) {
			return setPluginResultError("Exception");
		}
	}

	/**
			* Creates a symmetric key in the Android Key Store which can only be used after the user has
	* authenticated with fingerprint.
	*/
	public static void createKey() {
		// The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
		// for your flow. Use of keys is necessary if you need to know if the set of
		// enrolled fingerprints has changed.
		try {
			mKeyStore.load(null);
			// Set the alias of the entry in Android KeyStore where the key will appear
			// and the constrains (purposes) in the constructor of the Builder
			mKeyGenerator.init(new KeyGenParameterSpec.Builder(mClientId,
					KeyProperties.PURPOSE_ENCRYPT |
							KeyProperties.PURPOSE_DECRYPT)
					.setBlockModes(KeyProperties.BLOCK_MODE_CBC)
					// Require the user to authenticate with a fingerprint to authorize every use
					// of the key
					.setUserAuthenticationRequired(true)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
					.build());
			mKeyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
//			throw new RuntimeException(e);
			setPluginResultError("NoSuchAlgorithmException");
		} catch (InvalidAlgorithmParameterException e) {
//			throw new RuntimeException(e);
			setPluginResultError("InvalidAlgorithmParameterException");
		} catch (CertificateException e) {
//			throw new RuntimeException(e);
			setPluginResultError("CertificateException");
		} catch (IOException e) {
//			throw new RuntimeException(e);
			setPluginResultError("IOException");
		}
	}

	public static void onAuthenticated(boolean withFingerprint) {
		mPluginResult = new PluginResult(PluginResult.Status.OK);
		JSONObject resultJson = new JSONObject();
		try {
			if (withFingerprint) {
				// If the user has authenticated with fingerprint, verify that using cryptography and
				// then return the encrypted token

				byte[] encrypted = tryEncrypt();
				resultJson.put("withFingerprint", Base64.encodeToString(encrypted, 0 /* flags */));

			} else {
				// Authentication happened with backup password.
//				mCallbackContext.success("with password");
				resultJson.put("withPassword", true);
			}
		} catch (BadPaddingException e) {
			Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
		} catch (IllegalBlockSizeException e) {
			Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
		} catch (JSONException e) {
			Log.e(TAG, "Failed to set resultJson key value pair: " + e.getMessage());
		}
		mCallbackContext.success(resultJson);
		mCallbackContext.sendPluginResult(mPluginResult);
	}

	public static void onUsePasscode(boolean withFingerprint) {
		mPluginResult = new PluginResult(PluginResult.Status.OK);
		JSONObject resultJson = new JSONObject();
		try{
			resultJson.put("use_passcode", true);
		} catch (JSONException e) {
			Log.e(TAG, "Failed to set resultJson key value pair: " + e.getMessage());
		}

		mCallbackContext.success(resultJson);
		mCallbackContext.sendPluginResult(mPluginResult);

	}
	/**
	 * Tries to encrypt some data with the generated key in {@link #createKey} which is
	 * only works if the user has just authenticated via fingerprint.
	 */
	private static byte[] tryEncrypt() throws BadPaddingException, IllegalBlockSizeException {
		return mCipher.doFinal(mClientSecret.getBytes());
	}

	public static boolean setPluginResultError(String errorMessage) {
		mCallbackContext.error(errorMessage);
		mPluginResult = new PluginResult(PluginResult.Status.ERROR);
//		mCallbackContext.sendPluginResult(mPluginResult);
		return false;
	}
}