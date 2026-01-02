package com.jaylee.hardware_cert_tool

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyPair
import android.content.ClipData
import android.content.ClipboardManager
import android.security.KeyChain

class MainActivity : AppCompatActivity() {

    private lateinit var spinnerKeyType: Spinner
    private lateinit var editSubject: EditText
    private lateinit var editCertInput: EditText
    private lateinit var txtInstructions: TextView
    private lateinit var txtVerificationResult: TextView
    private lateinit var btnGenerateCsr: Button
    private lateinit var btnInstallManual: Button
    private lateinit var btnSelfSign: Button
    private lateinit var btnVerify: Button
    private lateinit var containerManual: LinearLayout
    private lateinit var containerSelfSign: LinearLayout
    private lateinit var radioGroup: RadioGroup

    private var currentKeyPair: KeyPair? = null
    private var waitingForInstall = false
    private val TARGET_ALIAS = "CorporateIdentity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        setTitle(R.string.app_name)

        spinnerKeyType = findViewById(R.id.spinnerKeyType)
        editSubject = findViewById(R.id.editSubject)
        txtInstructions = findViewById(R.id.txtInstructions)
        txtVerificationResult = findViewById(R.id.txtVerificationResult)
        
        containerManual = findViewById(R.id.containerManual)
        containerSelfSign = findViewById(R.id.containerSelfSign)
        
        radioGroup = findViewById(R.id.radioFlowType)
        
        btnGenerateCsr = findViewById(R.id.btnGenerateCsr)
        editCertInput = findViewById(R.id.editCertInput)
        btnInstallManual = findViewById(R.id.btnInstallManual)
        btnSelfSign = findViewById(R.id.btnSelfSign)
        btnVerify = findViewById(R.id.btnVerify)
        
        setupSpinner()
        setupListeners()
        updateInstructions("manual_start")
    }

    private fun setupSpinner() {
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, CryptoManager.KeyType.values())
        spinnerKeyType.adapter = adapter
    }

    private fun setupListeners() {
        radioGroup.setOnCheckedChangeListener { _, id ->
            containerManual.visibility = View.GONE
            containerSelfSign.visibility = View.GONE
            
            when (id) {
                R.id.radioManual -> {
                    containerManual.visibility = View.VISIBLE
                    updateInstructions("manual_start")
                }
                R.id.radioSelfSign -> {
                    containerSelfSign.visibility = View.VISIBLE
                    updateInstructions("self_sign_start")
                }
            }
        }

        btnGenerateCsr.setOnClickListener {
            val type = spinnerKeyType.selectedItem as CryptoManager.KeyType
            val subject = editSubject.text.toString()
            generateCsr(type, subject)
        }

        btnInstallManual.setOnClickListener {
            val certPem = editCertInput.text.toString()
            if (currentKeyPair != null && certPem.isNotBlank()) {
                installKey(certPem)
            } else {
                Toast.makeText(this, "Generate CSR first", Toast.LENGTH_SHORT).show()
            }
        }
        
        btnSelfSign.setOnClickListener {
            val type = spinnerKeyType.selectedItem as CryptoManager.KeyType
            val subject = editSubject.text.toString()
            performSelfSign(type, subject)
        }

        btnVerify.setOnClickListener {
            KeyChain.choosePrivateKeyAlias(this,
                { alias ->
                    if (alias != null) {
                        checkAliasSecurity(alias)
                    } else {
                        runOnUiThread {
                            txtVerificationResult.text = "Selection Cancelled"
                            txtVerificationResult.setTextColor(Color.GRAY)
                        }
                    }
                },
                null, null, null, -1, null
            )
        }
    }

    private fun checkAliasSecurity(alias: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val report = CryptoManager.getCertificateDetails(this@MainActivity, alias)
            
            withContext(Dispatchers.Main) {
                txtVerificationResult.text = report
                
                if (report.contains("STRONGBOX") || report.contains("TEE") || report.contains("HARDWARE")) {
                    txtVerificationResult.setTextColor(Color.parseColor("#006400")) // Green
                } else {
                    txtVerificationResult.setTextColor(Color.RED)
                }
            }
        }
    }

    private fun generateCsr(type: CryptoManager.KeyType, subject: String) {
        lifecycleScope.launch(Dispatchers.Default) {
            currentKeyPair = CryptoManager.generateKeyPair(type)
            val csrPem = CryptoManager.generateCsr(currentKeyPair!!, subject)

            withContext(Dispatchers.Main) {
                val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("CSR", csrPem))
                Toast.makeText(this@MainActivity, "CSR Copied to Clipboard!", Toast.LENGTH_LONG).show()
                
                editCertInput.setText("")
                editCertInput.hint = "Paste your signed certificate here..."
                updateInstructions("manual_csr_generated")
            }
        }
    }
    
    private fun performSelfSign(type: CryptoManager.KeyType, subject: String) {
        txtInstructions.text = "Generating Keys..."
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
            waitingForInstall = true
            val alias = "Identity_" + System.currentTimeMillis() / 1000
            CryptoManager.installToSystem(this, currentKeyPair!!, certPem, alias)
            updateInstructions("install_launched")
        } catch (e: Exception) {
            waitingForInstall = false
            txtInstructions.text = "Error: ${e.message}"
        }
    }

    private fun updateInstructions(state: String) {
        val text = when (state) {
            "manual_start" -> "1. Select Key Type\n2. Generate CSR\n3. Get it signed"
            "manual_csr_generated" -> "CSR Copied!\n4. Send to Admin\n5. Paste result below\n6. Click Install"
            "install_launched" -> "System Installer Opened..."
            "self_sign_start" -> "Generates a test Identity immediately."
            else -> ""
        }
        txtInstructions.text = text
    }
}
