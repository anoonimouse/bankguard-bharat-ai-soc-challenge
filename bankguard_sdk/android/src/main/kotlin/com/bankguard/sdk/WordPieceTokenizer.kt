package com.bankguard.sdk

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * WordPiece Tokenizer for on-device BERT sequence classification.
 * Converts input text into model input tensors (input_ids and attention_mask).
 */
class WordPieceTokenizer(context: Context) {
    private val vocab = mutableMapOf<String, Int>()

    init {
        try {
            context.assets.open("vocab.txt").use { input ->
                BufferedReader(InputStreamReader(input)).useLines { lines ->
                    lines.forEachIndexed { idx, token ->
                        vocab[token] = idx
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("BANKGUARD_TOKENIZER", "Failed to load vocab.txt asset: ${e.message}")
        }
    }

    /**
     * Tokenizes a given string and pads/truncates to maxLen.
     * Returns Pair(inputIds, attentionMask) matching model specifications.
     */
    fun tokenize(text: String, maxLen: Int = 128): Pair<LongArray, LongArray> {
        val tokens = mutableListOf<String>()
        tokens.add("[CLS]")
        
        // Split text by whitespace and special characters
        val words = text.lowercase().split(Regex("[\\s\\p{Punct}]+"))
        for (word in words) {
            if (word.isEmpty()) continue
            var start = 0
            while (start < word.length) {
                var end = word.length
                var curSubstr = ""
                while (start < end) {
                    var substr = word.substring(start, end)
                    if (start > 0) {
                        substr = "##$substr"
                    }
                    if (vocab.containsKey(substr)) {
                        curSubstr = substr
                        break
                    }
                    end--
                }
                if (curSubstr.isEmpty()) {
                    tokens.add("[UNK]")
                    break
                }
                tokens.add(curSubstr)
                start = end
            }
        }
        tokens.add("[SEP]")

        // Convert tokens to vocabulary IDs and build attention mask
        val inputIds = LongArray(maxLen) { 0L }
        val attentionMask = LongArray(maxLen) { 0L }
        
        val padId = vocab["[PAD]"]?.toLong() ?: 0L
        val unkId = vocab["[UNK]"]?.toLong() ?: 100L

        for (i in 0 until maxLen) {
            if (i < tokens.size) {
                val token = tokens[i]
                inputIds[i] = vocab[token]?.toLong() ?: unkId
                attentionMask[i] = 1L
            } else {
                inputIds[i] = padId
                attentionMask[i] = 0L
            }
        }
        return Pair(inputIds, attentionMask)
    }
}
