/// Generate fake CSS content for stealth cover traffic
pub(super) fn generate_fake_css(size_bytes: usize) -> Vec<u8> {
    let base_css = b"/* Generated CSS for cover traffic */\nbody{margin:0;padding:0;font-family:Arial,sans-serif}\n.container{max-width:1200px;margin:0 auto;padding:20px}\n.header{background:#333;color:#fff;padding:10px}\n.content{padding:20px;line-height:1.6}\n.footer{background:#f4f4f4;padding:10px;text-align:center}\n";
    let mut result = base_css.to_vec();

    // Pad with realistic CSS rules to reach target size
    while result.len() < size_bytes {
        let padding_rule = format!(
            ".rule-{}{{display:block;margin:{}px;padding:{}px;}}\n",
            result.len() % 1000,
            (result.len() % 20) + 5,
            (result.len() % 15) + 3
        );
        result.extend_from_slice(padding_rule.as_bytes());
    }
    result.truncate(size_bytes);
    result
}

/// Generate fake JavaScript content for stealth cover traffic
pub(super) fn generate_fake_js(size_bytes: usize) -> Vec<u8> {
    let base_js = b"// Generated JS for cover traffic\n(function(){\n'use strict';\nvar app={init:function(){console.log('App initialized')},utils:{debounce:function(func,wait){var timeout;return function(){clearTimeout(timeout);timeout=setTimeout(func,wait)}}}};\napp.init();\n";
    let mut result = base_js.to_vec();

    // Pad with realistic JS functions
    while result.len() < size_bytes {
        let func_name = format!("func{}", result.len() % 1000);
        let padding_func = format!("function {}(){{return {};}}\n", func_name, result.len() % 100);
        result.extend_from_slice(padding_func.as_bytes());
    }
    result.truncate(size_bytes);
    result
}

/// Generate fake image data for stealth cover traffic
pub(super) fn generate_fake_image_data(size_bytes: usize) -> Vec<u8> {
    // Fake JPEG header + random data
    let mut result = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG magic
    result.extend_from_slice(&[0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]); // JFIF

    // Fill with pseudo-random data that looks like compressed image
    let mut seed = 0x12345678u32;
    while result.len() < size_bytes - 2 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        result.push((seed >> 16) as u8);
    }

    // JPEG end marker
    result.extend_from_slice(&[0xFF, 0xD9]);
    result.truncate(size_bytes);
    result
}
