package com.jaylee.hardware_cert_tool

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.bottomnavigation.BottomNavigationView
import androidx.fragment.app.Fragment

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 1. Inflate the new layout
        setContentView(R.layout.activity_main)

        // 2. Find the Navigation Bar (This triggers the crash if XML is old)
        val navView = findViewById<BottomNavigationView>(R.id.nav_view)

        // 3. Set Default Screen (CreateFragment)
        if (savedInstanceState == null) {
            loadFragment(CreateFragment())
        }

        // 4. Handle Tab Clicks
        navView.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.navigation_create -> {
                    loadFragment(CreateFragment())
                    true
                }
                R.id.navigation_view -> {
                    loadFragment(ViewFragment())
                    true
                }
                else -> false
            }
        }
    }

    private fun loadFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment)
            .commit()
    }
}
