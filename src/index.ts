/**
 *   .7^:                                                                       ^^
 *    ~^^~^..                                                                 :^7.
 *     7^:^^^^^^::..                                                     ..:^~^^!
 *     .7^5GY7~^::^^~^^:.                                            .:^~~^:^!!7
 *      .7~G&&&#GY!^:::^^~~^:.                                  .:^~~^^::^?P#57.
 *        ~~Y&&&&&&#GY!^::::^^~~^:.                         .:^~~^^:::^?G&&&#!
 *         :~7G###&&&&&#P?~:::::^^~~^:.                  .^~~^^::::^7P#&#BBB^
 *           :~JPGGGB#&&&&&BJ~::::::^^~~^~^^^^^^^^^^:.:^~~^::::::!5#&#GGGBY
 *             .!YGGGGGB#&&&&&BJ~:::::::^~^::::::::^^~7~::::::~YB&&BGGGGB7
 *               .~5BGGGGG#&&&&&&P!^::::::::::::::::::::::::7G&&&BGGGGBP:
 *                  ^5GGGGGB&&&&&&&!::::::::::::::::::::::!B&&&#GGGGGG?
 *                    .!PGGGG#&&&&7:::::::::::::::::::::::^#&&#GGGGGY.
 *                       ^YGGB&&&Y:::::::::::::::::::::::::7&&GGGGY:
 *                        .7Y?!~^:^7!^::::::::^!?J!:::::::::GBGBY:
 *                    .^~~^::::::^:G&#P7^::::^5~?&&!::::~JG5~~~7~:.
 *                 .^~~^:::::::~J^:G&&&Y:!^!::YGPP5^:~^!7&&#~J!^:^^~~:.
 *               .~~^::::^^^:^!:~~:!#&&G:.7?~::^^^::~77.^&&Y75?7^::::^~~^.
 *             .^^:::^^~~~5!~:   :!^^JG#&B#Y:::::::::Y#B#GY!^.!?~!^^::::^~~:
 *           :~~^~~~~^.  ~7.      J?!^^~7YPY:::::::::YY?7~^.   .^J?^~~~^^::^~:
 *         .?7~^:..              .!~?J?7~^:::::::::::^~^.         :   .:^^~^^~!:
 *         .                     7^:^!??JJJ?7~^~!!~7~:                      ..:^
 *                              ~~::::~777???JJJJJY?
 */
export class Espeon {
  /**
   * ##  Espeon
   *
   * Light keyword-based encryption algorithm
   * @example
   * ```
   * const encryptionKey = "~Esp3eo0Nn-"
   *
   * // Disclaimer: Espeon encryption should be used only as a secondary layer
   * // on top of a secure hashing algorithm (i.e. Bcrypt, Scrypt, SHA512, Argon2).
   *
   * const encryptionService = new Espeon(encryptionKey)
   *
   * const hashedString = bcrypt.hash(sensitiveString, 10)
   * const doubleEncryptedString = encryptionService.encrypt(hashedString)
   * ```
   *
   */
  private readonly base: string;
  private readonly delimiter: string;

  /**
   * @param {string}  encryptionKey - Espeon requires fairly small encryption keys to use as a base. A valid key should contain 11 unique characters.
   */
  constructor(readonly encryptionKey: string) {
    const tokenizedKeyword = new Set(this.encryptionKey);

    if (tokenizedKeyword.size < 11) {
      throw new Error(
        "Encryption keyword should contain 11 unique characters."
      );
    }

    this.base = [...tokenizedKeyword]
      .slice(0, tokenizedKeyword.size - 1)
      .join("");
    this.delimiter = [...tokenizedKeyword][tokenizedKeyword.size - 1];
  }

  /**
   * 1. Codepoint of each character of the source string is split into digits.
   * 2. Each digit is translated into a character of the 'base' string using value as index.
   * 3. Translated characters are joined using delimiter as a separator.
   * @param sourceString - A string to be encrypted.
   */
  public encrypt(sourceString: string): string {
    const encryptedString = sourceString
      .split("")
      .map((char) => this.encryptUtf16Character(char))
      .join(this.delimiter);

    this.validateEncryption(sourceString, encryptedString);

    return encryptedString;
  }

  public decrypt(encryptedString: string): string {
    return encryptedString
      .split(this.delimiter)
      .map((encryptedChar) => this.decryptUtf16Character(encryptedChar))
      .join("");
  }

  private encryptUtf16Character(char: string): string {
    return char
      .codePointAt(0)!
      .toString()
      .split("")
      .map((stringifiedDigit) => this.base[parseInt(stringifiedDigit)])
      .join("");
  }

  private decryptUtf16Character(encryptedChar: string): string {
    return String.fromCodePoint(
      parseInt(
        encryptedChar
          .split("")
          .map((char) => this.base.indexOf(char).toString())
          .join("")
      )
    );
  }

  private validateEncryption(sourceString: string, encryptedString: string) {
    if (sourceString !== this.decrypt(encryptedString)) {
      throw new Error(
        JSON.stringify({
          message:
            "Couldn't validate encryption! Source string was malformed in the process!",
        })
      );
    }
  }
}
