package com.jaylee.hardware_cert_tool

import android.content.res.ColorStateList
import android.graphics.Color
import android.os.Bundle
import android.security.KeyChain
import android.util.TypedValue
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ViewFragment : Fragment() {

    private lateinit var txtResult: TextView
    private lateinit var btnVerify: Button

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_view, container, false)
        txtResult = view.findViewById(R.id.txtVerificationResult)
        btnVerify = view.findViewById(R.id.btnVerify)

        btnVerify.setOnClickListener {
            KeyChain.choosePrivateKeyAlias(requireActivity(),
                { alias ->
                    if (alias != null) {
                        checkAliasSecurity(alias)
                    } else {
                        activity?.runOnUiThread {
                            txtResult.text = "Selection Cancelled"
                            // Reset to default theme text color
                            txtResult.setTextColor(getThemeColor(com.google.android.material.R.attr.colorOnSurface))
                        }
                    }
                },
                null, null, null, -1, null
            )
        }
        return view
    }

    private fun checkAliasSecurity(alias: String) {
        viewLifecycleOwner.lifecycleScope.launch(Dispatchers.IO) {
            val report = CryptoManager.getCertificateDetails(requireContext(), alias)
            
            withContext(Dispatchers.Main) {
                txtResult.text = report
                
                // Logic: 
                // Secure = Standard Theme Text Color (Black in Day, White in Night)
                // Insecure = Red (Warning)
                
                val isSecure = report.contains("STRONGBOX") || report.contains("TEE") || report.contains("HARDWARE")
                
                if (isSecure) {
                    txtResult.setTextColor(getThemeColor(com.google.android.material.R.attr.colorOnSurface))
                } else {
                    txtResult.setTextColor(Color.RED)
                }
            }
        }
    }
    
    // Helper to dynamically get colors like 'colorOnSurface' from the current theme
    private fun getThemeColor(attrId: Int): Int {
        val typedValue = TypedValue()
        requireContext().theme.resolveAttribute(attrId, typedValue, true)
        return typedValue.data
    }
}
