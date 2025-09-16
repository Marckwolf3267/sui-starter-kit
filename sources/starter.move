module starter::PasswordGen {
    // Importa el módulo 'debug' de la biblioteca estándar de Sui.
    // 'debug::print' es una herramienta de depuración que nos permite
    // imprimir valores en la consola durante las pruebas, lo cual es
    // útil para verificar el funcionamiento del código.
    use std::debug;
    
    // ----------------------------
    // PRNG (Generador de Números Pseudoaleatorios)
    // ----------------------------
    
    // Esta es la estructura que define nuestro generador de números aleatorios.
    // - `state`: Es un número de 64 bits que cambia con cada generación para
    //   producir el siguiente número aleatorio.
    // - `has drop`: Es una habilidad que le dice al compilador de Move que
    //   esta estructura puede ser "descartada" de forma segura cuando ya no
    //   se necesita.
    public struct XorShift64 has drop {
        state: u64
    }

    // Inicializa el generador de números aleatorios.
    // - `seed`: Es un número inicial. Si dos generadores se inician con la
    //   misma semilla, producirán la misma secuencia de números aleatorios.
    //   Si la semilla es 0, se usa un valor predeterminado para evitar
    //   una secuencia trivial.
    public fun init_prng(seed: u64): XorShift64 {
        let st = if (seed == 0) { 0x9E3779B97F4A7C15u64 } else { seed };
        XorShift64 { state: st }
    }

    // Genera el siguiente número aleatorio de 64 bits.
    // Este algoritmo es el "XorShift".
    // no seguro para usos criptográficos.
    public fun next_u64(r: &mut XorShift64): u64 {
        let mut x = r.state;
        // Los 'xor shifts' son operaciones bit a bit que mezclan los bits
        // de una manera que parece aleatoria.
        x = x ^ (x << 13);
        x = x ^ (x >> 7);
        x = x ^ (x << 17);
        r.state = x; // Se actualiza el estado para la siguiente llamada
        x
    }

    // Genera un número aleatorio dentro de un rango específico.
    // Por ejemplo, si el `bound` es 10, esta función devolverá un número
    // entre 0 y 9.
    fun next_bounded(r: &mut XorShift64, bound: u64): u64 {
        let v = next_u64(r);
        v % bound // El operador de módulo asegura que el resultado esté dentro del rango
    }

    // ----------------------------
    // Construcción del Conjunto de Caracteres 
    // ----------------------------

    // Crea un vector de bytes que contiene todos los caracteres permitidos para la contraseña
    public fun build_charset(use_lower: bool, use_upper: bool, use_digits: bool, use_symbols: bool, avoid_ambiguous: bool): vector<u8> {
        let mut out = vector::empty<u8>();
        
        // Se añaden los caracteres de cada categoría si el parámetro es `true`.
        if (use_lower) {
            let lower = b"abcdefghijklmnopqrstuvwxyz";
            vector::append(&mut out, lower);
        };
        if (use_upper) {
            let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            vector::append(&mut out, upper);
        };
        if (use_digits) {
            let digits = b"0123456789";
            vector::append(&mut out, digits);
        };
        if (use_symbols) {
            let syms = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";
            vector::append(&mut out, syms);
        };

        // Si se pide evitar caracteres ambiguos, se eliminan del conjunto.
        if (avoid_ambiguous) {
            let ambiguous = b"0OIl1";
            let mut filtered = vector::empty<u8>();
            let mut i = 0;
            while (i < vector::length(&out)) {
                let ch = *vector::borrow(&out, i);
                if (!contains_byte(&ambiguous, ch)) {
                    vector::push_back(&mut filtered, ch);
                };
                i = i + 1;
            };
            filtered
        } else {
            out
        }
    }

    // Una función auxiliar que comprueba si un byte específico está presente
    // en un vector de bytes.
    fun contains_byte(v: &vector<u8>, b: u8): bool {
        let mut i = 0;
        while (i < vector::length(v)) {
            if (*vector::borrow(v, i) == b) {
                return true
            };
            i = i + 1;
        };
        false
    }

    // ----------------------------
    // Generación de Contraseña
    // ----------------------------
    
    // Genera una contraseña aleatoria de una longitud dada, usando el PRNG
    // y el conjunto de caracteres.
    public fun generate_password(prng: &mut XorShift64, length: u64, charset: &vector<u8>): vector<u8> {
        // Se asegura de que el conjunto de caracteres no esté vacío.
        let charset_len = vector::length(charset);
        assert!(charset_len > 0, 1);

        let mut out = vector::empty<u8>();
        let mut i = 0u64;
        while (i < length) {
            // Elige un índice aleatorio dentro del conjunto de caracteres
            // y añade ese carácter a la contraseña.
            let idx = next_bounded(prng, charset_len);
            let cb = *vector::borrow(charset, idx);
            vector::push_back(&mut out, cb);
            i = i + 1;
        };
        out
    }

    // Genera una contraseña con una "política de seguridad".
    // Esto asegura que la contraseña contenga al menos un carácter de cada
    // (minuscula, mayuscula, dígito, símbolo).
    public fun generate_with_policy(prng: &mut XorShift64, length: u64): vector<u8> {
        assert!(length >= 4, 2);
        let lower = b"abcdefghijklmnopqrstuvwxyz";
        let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = b"0123456789";
        let syms = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

        let mut out = vector::empty<u8>();
        // Añade un carácter aleatorio de cada categoría primero.
        vector::push_back(&mut out, *vector::borrow(&lower, next_bounded(prng, vector::length(&lower))));
        vector::push_back(&mut out, *vector::borrow(&upper, next_bounded(prng, vector::length(&upper))));
        vector::push_back(&mut out, *vector::borrow(&digits, next_bounded(prng, vector::length(&digits))));
        vector::push_back(&mut out, *vector::borrow(&syms, next_bounded(prng, vector::length(&syms))));

        let full = build_charset(true, true, true, true, false);

        // Rellena el resto de la contraseña con caracteres aleatorios del
        // conjunto completo.
        let mut remaining = length - 4;
        while (remaining > 0) {
            let idx = next_bounded(prng, vector::length(&full));
            vector::push_back(&mut out, *vector::borrow(&full, idx));
            remaining = remaining - 1;
        };

        // Mezcla los caracteres para que el orden sea completamente aleatorio
        // y la contraseña no empiece siempre con un patrón fijo.
        let n = vector::length(&out);
        let mut j = n;
        while (j > 1) {
            let j_idx = j - 1;
            let r_idx = next_u64(prng) % j;
            vector::swap(&mut out, j_idx, r_idx);
            j = j - 1;
        };
        
        out
    }

    // ----------------------------
    // Pruebas
    // ----------------------------
    
    // Una función de ejemplo pública que usa las funciones de generación
    // para crear una contraseña. Al ser pública, puede ser llamada
    // desde otras partes del código o desde el entorno de ejecución.
    public fun demo_example(): vector<u8> {
        let mut prng = init_prng(0x12345678u64);
        let charset = build_charset(true, true, true, true, true);
        generate_password(&mut prng, 16u64, &charset)
    }

    // Esta función de prueba se usa para verificar que el código funciona.
    // La anotación `#[test]` le dice a Move que es una prueba unitaria y
    // debe ser ejecutada por el comando `sui move test`.
    #[test]
    fun test_generate_password() {
        // Llama a la función de ejemplo para obtener la contraseña.
        let password = demo_example();
        
        // Imprime el resultado en la consola de depuración. Este es el
        // paso clave para ver la contraseña al ejecutar las pruebas.
        debug::print(&password);
    }
}
// La experimentacion es la base del conocimiento 