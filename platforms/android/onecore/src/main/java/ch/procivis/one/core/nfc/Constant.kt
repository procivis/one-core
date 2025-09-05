package ch.procivis.one.core.nfc

object Constant {
    object Apdu {
        const val MAX_C_APDU: Int = 255
        const val MAX_R_APDU: Int = 256

        const val INS_SELECT = 0xa4
        const val INS_READ_BINARY = 0xb0
        val PARAMS_SELECT_APPLICATION = Pair(0x04, 0x00)
        val PARAMS_SELECT_FILE = Pair(0x00, 0x0c)
    }

    /**
     * Type 4 Tag NDEF application ID
     */
    val ENGAGEMENT_APPLICATION = byteArrayOf(
        0xD2.toByte(),
        0x76.toByte(),
        0x00.toByte(),
        0x00.toByte(),
        0x85.toByte(),
        0x01.toByte(),
        0x01.toByte(),
    )
    
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