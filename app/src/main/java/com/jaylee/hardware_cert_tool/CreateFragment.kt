package com.jaylee.hardware_cert_tool

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.security.KeyChain
import android.util.Base64
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
    
    // We hold the KeyPair AND the Alias in memory for this session
    private var currentKeyPair: KeyPair? = null
    private var currentAlias: String? = null

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
        autoCompleteKeyType.setText(CryptoManager.KeyType.EC_P256.toString(), false)
    }
    
    private fun getSelectedKeyType(): CryptoManager.KeyType {
        val text = autoCompleteKeyType.text.toString()
        return try {
            CryptoManager.KeyType.valueOf(text)
        } catch (e: Exception) {
            CryptoManager.KeyType.EC_P256
        }
    }
    
    // Helper to Launch System Installer
    private fun promptSystemInstall(pemOrP12: Any, alias: String) {
        try {
            val intent = KeyChain.createInstallIntent()
            
            if (pemOrP12 is ByteArray) {
                // It's a P12 (PKCS#12)
                intent.putExtra(KeyChain.EXTRA_PKCS12, pemOrP12)
            } else if (pemOrP12 is String) {
                // It's a PEM Certificate
                val cleanPem = PemUtils.cleanPem(pemOrP12)
                val certBytes = Base64.decode(cleanPem, Base64.DEFAULT)
                intent.putExtra(KeyChain.EXTRA_CERTIFICATE, certBytes)
            }
            
            intent.putExtra(KeyChain.EXTRA_NAME, alias)
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(context, "System Install Failed: ${e.message}", Toast.LENGTH_LONG).show()
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

        // 1. GENERATE CSR
        btnGenerateCsr.setOnClickListener {
            val type = getSelectedKeyType()
            val subject = editSubject.text.toString()
            
            // Generate the PERMANENT alias now
            // We cannot rename Hardware Keys later, so we must use the final name here.
            val alias = "Cert_" + System.currentTimeMillis()

            lifecycleScope.launch(Dispatchers.Default) {
                try {
                    // Generate and Hold
                    currentKeyPair = CryptoManager.generateKeyPair(alias, type)
                    currentAlias = alias // Remember this alias!
                    
                    val csrPem = CryptoManager.generateCsr(currentKeyPair!!, subject)

                    withContext(Dispatchers.Main) {
                        val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("CSR", csrPem))
                        Toast.makeText(context, "CSR Copied! Key saved as $alias", Toast.LENGTH_SHORT).show()
                        
                        editCertInput.setText("")
                        editCertInput.hint = "Paste the signed certificate here..."
                        editCertInput.requestFocus()
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) { Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show() }
                }
            }
        }

        // 2. INSTALL MANUAL CERT
        btnInstallManual.setOnClickListener {
            val certPem = editCertInput.text.toString()
            
            // Check if we have a valid session
            if (currentKeyPair == null || currentAlias == null) {
                Toast.makeText(context, "Session Expired: Please generate a new CSR.", Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            
            if (certPem.isNotBlank()) {
                try {
                    // FIX: Use the SAME alias we generated earlier
                    val alias = currentAlias!! 
                    
                    CryptoManager.installToSystem(requireContext(), currentKeyPair!!, certPem, alias)
                    
                    Toast.makeText(context, "Success! Certificate Linked to Hardware Key (App Internal Only).", Toast.LENGTH_LONG).show()
                    
                    // Note: We do NOT call promptSystemInstall here.
                    // Since this is a Hardware Key (non-exportable), we cannot provide the Private Key to the System Installer.
                    // Providing just the certificate (EXTRA_CERTIFICATE) causes "private key required" error because the system expects a full credential.
                    
                    // Clear inputs
                    editCertInput.setText("")
                    
                } catch (e: Exception) {
                    Toast.makeText(context, "Mismatch Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            } else {
                Toast.makeText(context, "Paste the certificate first", Toast.LENGTH_SHORT).show()
            }
        }

        // 3. SELF SIGN & INSTALL
        btnSelfSign.setOnClickListener {
            val type = getSelectedKeyType()
            val subject = editSubject.text.toString()
            val alias = "Cert_" + System.currentTimeMillis()

            lifecycleScope.launch(Dispatchers.Default) {
                try {
                    // 1. Generate In-Memory KeyPair (Software backed)
                    val memoryKeyPair = CryptoManager.generateInMemoryKeyPair(type)
                    currentKeyPair = memoryKeyPair
                    currentAlias = alias
                    
                    // 2. Generate Self-Signed Cert
                    val certPem = CryptoManager.generateSelfSignedCert(memoryKeyPair, subject)
                    
                    // 3. Import to App's Secure Hardware Store (TEE)
                    // This allows the app to use it internally as well.
                    CryptoManager.installToSystem(requireContext(), memoryKeyPair, certPem, alias)
                    
                    // 4. Prepare System Install (P12 with Private Key)
                    val p12Bytes = CryptoManager.createP12(memoryKeyPair, certPem, alias)

                    withContext(Dispatchers.Main) {
                        Toast.makeText(context, "Success! Self-Signed Cert Generated.", Toast.LENGTH_SHORT).show()
                        promptSystemInstall(p12Bytes, alias)
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) { Toast.makeText(context, "Error: ${e.message}", Toast.LENGTH_LONG).show() }
                }
            }
        }
    }
}
