package shadowaead_2022

type MethodOption func(*Method)

func MethodOptionEncryptedProtocolExtension() MethodOption {
	return func(method *Method) {
		method.encryptedProtocolExtension = true
	}
}
