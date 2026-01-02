package com.jaylee.hardware_cert_tool

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyPair
import com.google.android.material.textfield.TextInputLayout

class CreateFragment : Fragment() {

    private lateinit var autoCompleteKeyType: AutoCompleteTextView
    private lateinit var editSubject: EditText
    private lateinit var radioGroup: RadioGroup
    private lateinit var containerManual: LinearLayout
    private lateinit var containerSelfSign: LinearLayout
    private lateinit var btnGenerateCsr: Button
    private lateinit var editCertInput: EditText
    private lateinit var btnInstallManual: Button
    private lateinit var btnSelfSign: Button
    
    private var currentKeyPair: KeyPair? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_create, container, false)

        autoCompleteKeyType = view.findViewById(R.id.autoCompleteKeyType)
        editSubject = view.findViewById(R.id.editSubject)
        radioGroup = view.findViewById(R.id.radioFlowType)
        containerManual = view.findViewById(R.id.containerManual)
        containerSelfSign = view.findViewById(R.id.containerSelfSign)
        btnGenerateCsr = view.findViewById(R.id.btnGenerateCsr)
        editCertInput = view.findViewById(R.id.editCertInput)
        btnInstallManual = view.findViewById(R.id.btnInstallManual)
        btnSelfSign = view.findViewById(R.id.btnSelfSign)

        setupDropdown()
        setupListeners()
        
        return view
    }

    private fun setupDropdown() {
        val keyTypes = CryptoManager.KeyType.values()
        val adapter = ArrayAdapter(requireContext(), android.R.layout.simple_dropdown_item_1line, keyTypes)
        autoCompleteKeyType.setAdapter(adapter)
        
        // CHANGED: Explicitly set default to EC_P256
        val defaultType = CryptoManager.KeyType.EC_P256
        autoCompleteKeyType.setText(defaultType.toString(), false)
    }
    
    private fun getSelectedKeyType(): CryptoManager.KeyType {
        val text = autoCompleteKeyType.text.toString()
        return try {
            CryptoManager.KeyType.valueOf(text)
        } catch (e: Exception) {
            CryptoManager.KeyType.EC_P256
        }
    }

    private fun setupListeners() {
        radioGroup.setOnCheckedChangeListener { _, id ->
            containerManual.visibility = View.GONE
            containerSelfSign.visibility = View.GONE
            when (id) {
                R.id.radioManual -> containerManual.visibility = View.VISIBLE
                R.id.radioSelfSign -> containerSelfSign.visibility = View.VISIBLE
            }
        }

        btnGenerateCsr.setOnClickListener {
            val type = getSelectedKeyType()
            val subject = editSubject.text.toString()
            generateCsr(type, subject)
        }

        btnInstallManual.setOnClickListener {
            val certPem = editCertInput.text.toString()
            if (currentKeyPair != null && certPem.isNotBlank()) {
                installKey(certPem)
            } else {
                Toast.makeText(context, "Generate CSR first", Toast.LENGTH_SHORT).show()
            }
        }

        btnSelfSign.setOnClickListener {
            val type = getSelectedKeyType()
            val subject = editSubject.text.toString()
            performSelfSign(type, subject)
        }
    }

    private fun generateCsr(type: CryptoManager.KeyType, subject: String) {
        lifecycleScope.launch(Dispatchers.Default) {
            currentKeyPair = CryptoManager.generateKeyPair(type)
            val csrPem = CryptoManager.generateCsr(currentKeyPair!!, subject)

            withContext(Dispatchers.Main) {
                val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("CSR", csrPem))
                Toast.makeText(context, "CSR Copied to Clipboard!", Toast.LENGTH_LONG).show()
                editCertInput.setText("")
                editCertInput.hint = "Paste your signed certificate here..."
            }
        }
    }

    private fun performSelfSign(type: CryptoManager.KeyType, subject: String) {
        Toast.makeText(context, "Generating...", Toast.LENGTH_SHORT).show()
        lifecycleScope.launch(Dispatchers.Default) {
            currentKeyPair = CryptoManager.generateKeyPair(type)
            val certPem = CryptoManager.generateSelfSignedCert(currentKeyPair!!, subject)
            withContext(Dispatchers.Main) {
                installKey(certPem)
            }
        }
    }

    private fun installKey(certPem: String) {
        try {
            val alias = "Certificate_" + System.currentTimeMillis() / 1000
            CryptoManager.installToSystem(requireContext(), currentKeyPair!!, certPem, alias)
        } catch (e: Exception) {
            Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
}
