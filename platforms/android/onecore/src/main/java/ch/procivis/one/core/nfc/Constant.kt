package ch.procivis.one.core.nfc

object Constant {
    object Apdu {
        const val MAX_C_APDU: Int = 255
        const val MAX_R_APDU: Int = 256
    }

    object HceCommand {
        val SELECT_APPLICATION = byteArrayOf(
            0x00.toByte(), // CLA	- Class - Class of instruction
            0xA4.toByte(), // INS	- Instruction - Instruction code
            0x04.toByte(), // P1	- Parameter 1 - Instruction parameter 1
            0x00.toByte(), // P2	- Parameter 2 - Instruction parameter 2
            0x07.toByte(), // Lc field	- Number of bytes present in the data field of the command
            0xD2.toByte(),
            0x76.toByte(),
            0x00.toByte(),
            0x00.toByte(),
            0x85.toByte(),
            0x01.toByte(),
            0x01.toByte(), // NDEF Tag Application name
            0x00.toByte()  // Le field	- Maximum number of bytes expected in the data field of the response to the command
        )

        val SELECT_FILE = byteArrayOf(
            0x00.toByte(), // CLA	- Class - Class of instruction
            0xa4.toByte(), // INS	- Instruction - Instruction code
            0x00.toByte(), // P1	- Parameter 1 - Instruction parameter 1
            0x0c.toByte(), // P2	- Parameter 2 - Instruction parameter 2
            0x02.toByte(), // Lc field	- Number of bytes present in the data field of the command
        )

        val NDEF_READ_BINARY = byteArrayOf(
            0x00.toByte(), // Class byte (CLA)
            0xb0.toByte() // Instruction byte (INS) for ReadBinary command
        )
    }

    object HceResponse {
        val A_OKAY = byteArrayOf(
            0x90.toByte(), // SW1	Status byte 1 - Command processing status
            0x00.toByte() // SW2	Status byte 2 - Command processing qualifier
        )

        val A_ERROR = byteArrayOf(
            0x6A.toByte(), // SW1	Status byte 1 - Command processing status
            0x82.toByte() // SW2	Status byte 2 - Command processing qualifier
        )

        val A_NOT_AVAILABLE = byteArrayOf(
            0x69.toByte(), // SW1	Status byte 1 - Command processing status
            0x85.toByte() // SW2	Status byte 2 - Command processing qualifier
        )
    }

    object HceFile {
        val CAPABILITY_CONTAINER_ID = byteArrayOf(
            0xe1.toByte(), 0x03.toByte() // file identifier of the CC file
        )
        val NDEF_FILE_ID = byteArrayOf(
            0xe1.toByte(), 0x04.toByte()
        )
    }
}