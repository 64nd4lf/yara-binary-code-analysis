rule binary_code_analysis{
        meta:
                author = "Raghu Pusapati"
                description = "Binary code analysis with Yara"
        strings:
                $static_data0 = {c7 45 fc fe ff ff ff 8b 45 e0 e8 0a 02 00 00 c3}
		$static_data1 = {33 c9 39 b0 e8 00 40 00 0f 95 c1 89 4d e4}
		$static_data2 = {6a 0a 59}

		$dynamic_data0 = {6a 58 68 ?? ?? ?? 00 e8 25 03 00 00 8d 45 98 50 ff 15 ?? ?? ?? 00 33 f6 39 35 ?? ?? ?? 00 75 0b}
		$dynamic_data1 = {56 56 6a 01 56 ff 15 ?? ?? ?? 00}
		$dynamic_data2 = {51 50 56 68 00 00 40 00 e8 ?? ?? ?? 00 89 45 e0 39 75 e4 75 06}
		$dynamic_data3 = {50 e8 ?? ?? ?? 00}
		
		$code_range = {e8 ?? ?? ?? 00 [8] 85 c0 79 08}

		$byte_alternatives = {6a (1c|10|1b|08|09) e8 ?? ?? ?? ??}

        condition:
                ($static_data0 or $static_data1 or $static_data2) and ($dynamic_data0 or $dynamic_data1 or $dynamic_data2 or $dynamic_data3) and ($code_range) and ($byte_alternatives)
}

