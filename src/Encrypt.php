<?php

namespace Oonix;

/**
 * Encrypted object wrapper
 *
 * Wrap generic objects and specify attributes to be encrypted prior to setting.
 * Public attributes and methods of the wrapped object are exposed with magic methods.
 * 
 * @package oonix/encryption-wrapper
 * @author Arran Schlosberg <arran@oonix.com.au>
 * @license GPL-3.0
 */
class Encrypt {

	/**
	 * Cipher method for use with openssl_[en|de]crypt()
	 *
	 * @var string
	 * @access private
	 */
	private $_cipher;
	
	/**
	 * Should we allow the initialisation vector for the encryption to be derived from a cryptographically weak PRNG
	 *
	 * @var bool
	 * @access private
	 */
	private $_allow_weak_iv;
	
	/**
	 * Options to be passed to openssl_[en|de]crypt()
	 * OPENSSL_RAW_DATA and/or OPENSSL_ZERO_PADDING
	 * Use of OPENSSL_RAW_DATA will store cipher text and IV concatenated as raw bytes, otherwise as base 64 encoded strings
	 *
	 * @var int
	 * @access private
	 */
	private $_openssl_options;
	
	/**
	 * Symmetric encryption key
	 *
	 * @var string
	 * @access private
	 */
	private $_key;
	
	/**
	 * The object being wrapped such that specified attributes are encrypted prior to being set
	 *
	 * @var object
	 * @access private
	 */
	private $_obj;
	
	/**
	 * Array of keys that should be encrypted prior to storage, keys are ignored
	 *
	 * @var array
	 * @access private
	 */
	private $_encrypted;

	/**
	 * Constructor
	 *
	 * Store the configuration directives. Implements checks and then stores each in the equivalent private parameter.
	 *
	 * @param object $obj				See attribute $_obj.
	 * @param string $key				See attribute $_key.
	 * @param string $cipher			See attribute $_cipher.
	 * @param array $config				See default directives within the function code for details.
	 * @access public
	 */
	public function __construct($obj, $key, $cipher, $config = array()){
		if(!function_exists('openssl_encrypt')){
			throw new EncryptedSessionException("OpenSSL encryption functions required.");
		}
		
		if(!in_array($cipher, openssl_get_cipher_methods(true))){
			throw new EncryptedSessionException("The cipher '{$cipher}' is not available. Use openssl_get_cipher_methods() for a list of available methods.");
		}
		
		/**
		 * Default configuration directives. See respective class attributes for more details. Checks are implemented below.
		 */
		$config = array_replace_recursive(array(
			"encrypted" => array(),
			"openssl_options" => 0,
			"allow_weak_iv" => false
		), $config);

		$this->_obj = $obj;
		$this->_key = $key;
		$this->_cipher = $cipher;
		$this->_allow_weak_iv = $config['allow_weak_iv']===true;
		$this->_openssl_options = is_int($config['openssl_options']) ? $config['openssl_options'] : 0;
		$this->_encrypted = is_array($config['encrypted']) ? $config['encrypted'] : array($config['encrypted']);
	}
	
	/**
	 * Convenience function to check if OpenSSL options specify raw data usage; __get and __set will treat cipher text in the same manner.
	 *
	 * @access public
	 * @return bool
	 */
	public function useRaw(){
		return ($this->_openssl_options & OPENSSL_RAW_DATA) > 0;
	}
	
	/**
	 * Magic "setter"
	 * 
	 * Intercept keys that are to be encrypted prior to storage.
	 * Generates a unique IV each time and ensures that a cryptographically strong PRNG was used unless we specifically allow otherwise.
	 * Concatenate the IV with the cipher_text.
	 * Pass on the stored data (encrypted or otherwise) to the wrapped object for storage.
	 *
	 * @param string $key			Attribute being set.
	 * @param string $plain_text	Plain text data.
	 * @access public
	 */
	public function __set($key, $plain_text){
		if(in_array($key, $this->_encrypted)){
			$strong = false;
			$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->_cipher), $strong);
			if(!$strong && $this->_allow_weak_iv!==true){
				throw new EncryptException("A cryptographically weak algorithm was used in the generation of the initialisation vector.");
			}
			$cipher_text = openssl_encrypt($plain_text, $this->_cipher, $this->_key, $this->_openssl_options, $iv);
			$store = ($this->useRaw() ? $iv : base64_encode($iv)).$cipher_text;
		}
		else {
			$store = $plain_text;
		}
		$this->_obj->$key = $store;
	}
	
	/**
	 * Magic "getter"
	 *
	 * Retrieve stored data from the wrapped object and, if necessary decrypt it.
	 * 
	 * @param string $key		Attribute being retrieved.
	 * @access public
	 * @return mixed
	 */
	public function __get($key){
		$stored = $this->_obj->$key;
		if(!in_array($key, $this->_encrypted)){
			return $stored;
		}
		$len = openssl_cipher_iv_length($this->_cipher);
		if($this->useRaw()){
			$iv = substr($stored, 0, $len);
			$cipher_text = substr($stored, $len);
		}
		else {
			/**
			 * The number of = used to pad base 64 strings is dependent on the number of bytes in the final 2-byte grouping; = for even and == for odd
			 */
			$iv_pad = ($len % 2) ? "=" : "==";
			list($iv, $cipher_text) = explode($iv_pad, $stored, 2);
			$iv = base64_decode("{$iv}{$iv_pad}");
		}
		return openssl_decrypt($cipher_text, $this->_cipher, $this->_key, $this->_openssl_options, $iv);
	}

	/**
	 * Magic "caller"
	 *
	 * Provide access to the wrapped object's methods.
	 * 
	 * @param string $name	Name of the wrapped method to be called.
	 * @param array $args	Array of arguments to be passed to the wrapped object's method.
	 * @access public
	 * @return mixed			Dependent on the wrapped method.
	 */
	public function __call($name, $args){
		return call_user_func_array(array($this->_obj, $name), $args);
	}
	
	/**
	 * Magic "isset"
	 *
	 * @param string $key	Name of the potentially existent wrapped attribute.
	 * @access public
	 * @return bool
	 */
	public function __isset($key){
		return isset($this->_obj->$key);
	}
	
	/**
	 * Magic "unset"
	 *
	 * @param string $key	Name of the wrapped attribute being removed.
	 * @access public
	 */
	public function __unset($key){
		unset($this->_obj->$key);
	}

}

?>
