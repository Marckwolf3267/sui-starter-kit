module starter::PasswordGen {

    // 'state' es el valor interno que cambia con cada llamada para producir
    // el siguiente número.
    // La habilidad 'drop' permite que el compilador descarte esta estructura
    // automáticamente cuando ya no es necesaria, previniendo errores de
    // gestión de recursos.
    public struct XorShift64 has drop {
        state: u64
    }

    // Inicializa el generador PRNG con una semilla.
    // Si la semilla es 0, usa un valor predeterminado para asegurar que no se
    // genere una secuencia predecible desde el inicio.
    public fun init_prng(seed: u64): XorShift64 {
        let st = if (seed == 0) { 0x9E3779B97F4A7C15u64 } else { seed };
        XorShift64 { state: st }
    }

    // Genera el siguiente número pseudoaleatorio de 64 bits.
    // Implementa el algoritmo xorshift64.
    public fun next_u64(r: &mut XorShift64): u64 {
        let mut x = r.state;
        x = x ^ (x << 13);
        x = x ^ (x >> 7);
        x = x ^ (x << 17);
        r.state = x;
        x
    }

    // Genera un número pseudoaleatorio dentro de un límite ('bound').
    // Usa la operación de módulo (%) para asegurar que el resultado esté
    // en el rango de 0 a `bound - 1`.
    fun next_bounded(r: &mut XorShift64, bound: u64): u64 {
        let v = next_u64(r);
        v % bound
    }

    // Construye un vector de bytes que representa el conjunto de caracteres
    // para la contraseña, basado en los parámetros de entrada.
    public fun build_charset(use_lower: bool, use_upper: bool, use_digits: bool, use_symbols: bool, avoid_ambiguous: bool): vector<u8> {
        // Se inicializa un vector vacío para almacenar el conjunto de caracteres.
        let mut out = vector::empty<u8>();
        
        // Se añaden los caracteres según los parámetros.
        if (use_lower) {
            let lower = b"abcdefghijklmnopqrstuvwxyz";
            let mut i = 0;
            while (i < vector::length(&lower)) {
                vector::push_back(&mut out, *vector::borrow(&lower, i));
                i = i + 1;
            };
        };
        if (use_upper) {
            let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let mut i = 0;
            while (i < vector::length(&upper)) {
                vector::push_back(&mut out, *vector::borrow(&upper, i));
                i = i + 1;
            };
        };
        if (use_digits) {
            let digits = b"0123456789";
            let mut i = 0;
            while (i < vector::length(&digits)) {
                vector::push_back(&mut out, *vector::borrow(&digits, i));
                i = i + 1;
            };
        };
        if (use_symbols) {
            let syms = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";
            let mut i = 0;
            while (i < vector::length(&syms)) {
                vector::push_back(&mut out, *vector::borrow(&syms, i));
                i = i + 1;
            };
        };

        // Si 'avoid_ambiguous' es verdadero, se eliminan los caracteres
        // que pueden confundirse (como '0' y 'O').
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

    // Comprueba si un vector de bytes contiene un byte específico.
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

    // Genera una contraseña con una longitud y un conjunto de caracteres
    // dados, usando el PRNG.
    public fun generate_password(prng: &mut XorShift64, length: u64, charset: &vector<u8>): vector<u8> {
        // Se asegura de que el conjunto de caracteres no esté vacío.
        let charset_len = vector::length(charset);
        assert!(charset_len > 0, 1);

        let mut out = vector::empty<u8>();
        let mut i = 0u64;
        while (i < length) {
            // Selecciona un carácter aleatorio del conjunto y lo añade a la contraseña.
            let idx = next_bounded(prng, charset_len);
            let cb = *vector::borrow(charset, idx);
            vector::push_back(&mut out, cb);
            i = i + 1;
        };
        out
    }

    // Genera una contraseña con una política específica:
    // asegura que la contraseña contenga al menos una letra minúscula, una
    // letra mayúscula, un dígito y un símbolo. Luego, el resto de los
    // caracteres se generan de forma aleatoria.
    public fun generate_with_policy(prng: &mut XorShift64, length: u64): vector<u8> {
        assert!(length >= 4, 2);
        let lower = b"abcdefghijklmnopqrstuvwxyz";
        let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = b"0123456789";
        let syms = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";

        let mut out = vector::empty<u8>();
        // Añade un carácter de cada categoría para asegurar la política.
        vector::push_back(&mut out, *vector::borrow(&lower, next_bounded(prng, vector::length(&lower))));
        vector::push_back(&mut out, *vector::borrow(&upper, next_bounded(prng, vector::length(&upper))));
        vector::push_back(&mut out, *vector::borrow(&digits, next_bounded(prng, vector::length(&digits))));
        vector::push_back(&mut out, *vector::borrow(&syms, next_bounded(prng, vector::length(&syms))));

        // Construye el conjunto de caracteres completo para el resto de la contraseña.
        let full = build_charset(true, true, true, true, false);

        // Añade el resto de caracteres para alcanzar la longitud deseada.
        let mut remaining = length - 4;
        while (remaining > 0) {
            let idx = next_bounded(prng, vector::length(&full));
            vector::push_back(&mut out, *vector::borrow(&full, idx));
            remaining = remaining - 1;
        };

        // Mezcla los caracteres de forma aleatoria (Fisher-Yates) para que no
        // se sigan los primeros 4 caracteres.
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

    // Una función de ejemplo para demostrar cómo se usa la lógica de generación.
    // Devuelve el vector de bytes de la contraseña.
    public fun demo_example(): vector<u8> {
        let mut prng = init_prng(0x12345678u64);
        let charset = build_charset(true, true, true, true, true);
        generate_password(&mut prng, 16u64, &charset)
    }

    // Función de prueba que muestra el resultado de la generación de la contraseña.
    // #[test] es una anotación especial que le dice al compilador de Move que
    // esta función es una prueba unitaria.
    #[test]
    fun test_generate_password() {
        // Llama a la función de ejemplo para generar la contraseña.
        let password = demo_example();
        
        // Imprime el vector de bytes de la contraseña en la salida de la prueba.
        // Esto permite ver el resultado en la consola al ejecutar 'sui move test'.
        debug::print(&password);
    }
}
// La experimentacion es la base del conocimiento 