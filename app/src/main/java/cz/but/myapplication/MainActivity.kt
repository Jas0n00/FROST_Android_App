package cz.but.myapplication

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity


class MainActivity : AppCompatActivity() {

    private lateinit var participantsTextView: TextView
    private lateinit var thresholdTextView: TextView
    private lateinit var messageEditText: EditText
    private lateinit var signersContainer: LinearLayout
    private lateinit var verifiersContainer: LinearLayout
    private lateinit var buttonSign: Button
    private lateinit var buttonVerify: Button
    private lateinit var signatureTextView: TextView
    private lateinit var hashTextView: TextView

    private var maxSigners = 0 // Holds the maximum allowed signers based on threshold
    private var selectedSigners = mutableListOf<Int>()
    private var selectedVerifiers = mutableListOf<Int>()

    companion object {
        init {
            try {
                System.loadLibrary("frost")
                Log.d("MainActivity", "Native library loaded successfully.")
            } catch (e: UnsatisfiedLinkError) {
                Log.e("MainActivity", "Failed to load native library: ${e.message}")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        try {
            // Initialize views
            participantsTextView = findViewById(R.id.participantsTextView)
            thresholdTextView = findViewById(R.id.thresholdTextView)
            messageEditText = findViewById(R.id.messageEditText)
            signersContainer = findViewById(R.id.signersContainer)
            verifiersContainer = findViewById(R.id.verifiersContainer)
            buttonSign = findViewById(R.id.applyButton)
            buttonVerify = findViewById(R.id.applyButton2)
            signatureTextView = findViewById(R.id.signatureTextView)
            hashTextView = findViewById(R.id.hashTextView)

            // Set default prompts for TextViews
            participantsTextView.text = "Select number of participants"
            thresholdTextView.text = "Select number of signers"

            // Initially disable the apply button until all conditions are met
            buttonSign.isEnabled = false

            // Set click listeners to show dialogs
            participantsTextView.setOnClickListener { showParticipantsDialog() }
            thresholdTextView.setOnClickListener { showThresholdDialog() }

            // Add TextWatcher to messageEditText to monitor changes
            messageEditText.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: Editable?) {
                    validateSelections()
                }
            })


            // Apply button logic
            buttonSign.setOnClickListener {
                val threshold = thresholdTextView.text.toString().toIntOrNull()
                val participants = participantsTextView.text.toString().toIntOrNull()
                val message = messageEditText.text.toString()

                if (threshold == null || participants == null || message.isBlank()) {
                    Toast.makeText(this, "Please fill all fields correctly.", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }

                val selectedParticipants = mutableListOf<Int>()
                for (i in 0 until signersContainer.childCount) {
                    val checkBox = signersContainer.getChildAt(i) as CheckBox
                    if (checkBox.isChecked) {
                        selectedParticipants.add(i)
                    }
                }

                if (selectedParticipants.size < threshold) {
                    Toast.makeText(this, "Please select enough participants.", Toast.LENGTH_SHORT).show()
                }
                else {
                    // Convert indices to int array
                    val indicesArray = selectedParticipants.toIntArray()

                    try {
                        // Trigger native function
                        executeSigning(threshold, participants, message, indicesArray)
                        Toast.makeText(
                            this,
                            "Signing triggered with participants: $selectedParticipants",
                            Toast.LENGTH_LONG
                        ).show()
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Error executing signing: ${e.message}")
                        Toast.makeText(this, "Error during signing: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }

            buttonVerify.setOnClickListener { handleVerifyButtonClick() }

        } catch (e: Exception) {
            Log.e("MainActivity", "Error during initialization: ${e.message}")
            Toast.makeText(this, "Initialization error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun handleVerifyButtonClick() {
        val message = messageEditText.text.toString()

        if (message.isBlank()) {
            Toast.makeText(this, "Message cannot be empty for verification.", Toast.LENGTH_SHORT).show()
            return
        }

        val selectedParticipants = mutableListOf<Int>()
        for (i in 0 until verifiersContainer.childCount) {
            val checkBox = verifiersContainer.getChildAt(i) as CheckBox
            if (checkBox.isChecked) {
                selectedParticipants.add(i)
            }
        }

        if (selectedParticipants.isEmpty()) {
            Toast.makeText(this, "Please select at least one verifier.", Toast.LENGTH_SHORT).show()
            return
        }

        val indicesArray = selectedParticipants.toIntArray()

        try {
            val isValid = verifySignature(message, indicesArray)

            val resultMessage = if (isValid) {
                "Signature verification succeeded!"
            } else {
                "Signature verification failed!"
            }

            Toast.makeText(this, resultMessage, Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Log.e("MainActivity", "Error during verification: ${e.message}")
            Toast.makeText(this, "Verification error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    // Show dialog to select number of participants
    private fun showParticipantsDialog() {
        val values = arrayOf(2, 3, 4, 5)
        val builder = AlertDialog.Builder(this)
        builder.setTitle("Select number of participants")
            .setItems(values.map { it.toString() }.toTypedArray()) { _, which ->
                val selectedParticipants = values[which]
                participantsTextView.text = selectedParticipants.toString()
                createCheckboxes(selectedParticipants)
                maxSigners = selectedParticipants
                // Reset threshold selection
                thresholdTextView.text = "Select number of signers"
                validateSelections()
            }
        builder.show()
    }

    // Show dialog to select number of signers
    private fun showThresholdDialog() {
        if (maxSigners < 2) {
            Toast.makeText(this, "Please select participants first", Toast.LENGTH_SHORT).show()
            return
        }
        val values = (2..maxSigners).toList()
        if (values.isEmpty()) {
            Toast.makeText(this, "No signers can be selected. Please select participants first.", Toast.LENGTH_SHORT).show()
            return
        }
        val builder = AlertDialog.Builder(this)
        builder.setTitle("Select number of signers")
            .setItems(values.map { it.toString() }.toTypedArray()) { _, which ->
                val selectedThreshold = values[which]
                thresholdTextView.text = selectedThreshold.toString()
                validateSelections()
            }
        builder.show()
    }

    private fun createCheckboxes(participants: Int) {
        signersContainer.removeAllViews()
        verifiersContainer.removeAllViews()

        for (i in 0 until participants) {
            val checkBox = CheckBox(this)
            checkBox.text = "Participant ${i + 1}"
            checkBox.id = i
            checkBox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedSigners.add(i)
                } else {
                    selectedSigners.remove(i)
                }
                limitSelectedCheckboxes()
                validateSelections()
            }
            signersContainer.addView(checkBox)

            val verifierCheckBox = CheckBox(this)
            verifierCheckBox.text = "Verifier ${i + 1}"
            verifierCheckBox.id = i
            verifierCheckBox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedVerifiers.add(i)
                } else {
                    selectedVerifiers.remove(i)
                }
            }
            verifiersContainer.addView(verifierCheckBox)
        }
    }
    // Dynamically create checkboxes based on the number of participants
   /* private fun createCheckboxes(participants: Int) {
        // Clear the container first
        signersContainer.removeAllViews()
        verifiersContainer.removeAllViews()

        // Create checkboxes based on the participants count
        for (i in 0 until participants) {
            val checkBox = CheckBox(this)
            checkBox.text = "Participant ${i + 1}"
            checkBox.id = i
            checkBox.setOnCheckedChangeListener { _, _ ->
                // Handle the selection limit logic here if needed
                limitSelectedCheckboxes()
                validateSelections()
            }
            signersContainer.addView(checkBox)
        }

        // After creating checkboxes, reset threshold selection
        thresholdTextView.text = "Select number of signers"
    }*/

    // Function to limit the number of selected checkboxes based on maxSigners
    private fun limitSelectedCheckboxes() {
        val checkboxes = (0 until signersContainer.childCount).map {
            signersContainer.getChildAt(it) as CheckBox
        }
        val selectedCount = checkboxes.count { it.isChecked }

        if (selectedCount > maxSigners) {
            Toast.makeText(this, "You cannot select more than $maxSigners participants.", Toast.LENGTH_SHORT).show()
            // Deselect the last checked checkbox
            val lastChecked = checkboxes.lastOrNull { it.isChecked }
            lastChecked?.isChecked = false
        }
    }

    // Validate if all conditions are met to enable the apply button
    private fun validateSelections() {
        val threshold = thresholdTextView.text.toString().toIntOrNull()
        val participants = participantsTextView.text.toString().toIntOrNull()
        val message = messageEditText.text.toString()

        val selectedCount = signersContainer.childCount.takeIf { it > 0 }?.let {
            (0 until it).count { i -> (signersContainer.getChildAt(i) as CheckBox).isChecked }
        } ?: 0

        val isThresholdValid = threshold != null && threshold >= 2 && threshold <= maxSigners
        val isParticipantsValid = participants != null && participants >= 2
        val isMessageValid = message.isNotBlank()
        val isSelectionValid = selectedCount == threshold && selectedCount <= maxSigners

        // Apply button should be enabled only when selection is valid
        buttonSign.isEnabled = isThresholdValid && isParticipantsValid && isMessageValid && isSelectionValid
    }

    // This method will be called once signing is completed in JNI
    fun onSigningCompleted(signatureHex: String?, hashHex: String?) {
        signatureTextView.text = signatureHex ?: "Signature generation failed"
        hashTextView.text = hashHex ?: "Hash generation failed"
    }


    // Native function declaration
    external fun executeSigning(threshold: Int, participants: Int, message: String, indices: IntArray)
    external fun verifySignature(message: String, verifiers: IntArray): Boolean
}

