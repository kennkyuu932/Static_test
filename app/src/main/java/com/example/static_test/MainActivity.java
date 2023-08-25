package com.example.static_test;

import static android.content.ContentValues.TAG;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.example.static_test.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'static_test' library on application startup.
    static {
        System.loadLibrary("static_test");
//        System.loadLibrary("crypto");
//        System.loadLibrary("ssl");
//        System.loadLibrary("decrepit");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());

        //Log.d(TAG, "cryptoTest: "+cryptoTest());
        //Log.d(TAG, "eckeyTest: "+eckeyTest());
        //Log.d(TAG, "ECDSATest: "+ECDSATest());
        //Log.d(TAG, "RSATest: "+RSATest());
        Log.d(TAG, "SHATest: "+SHATest());
        //Log.d(TAG, "CastTest: "+CastTest());
    }

    /**
     * A native method that is implemented by the 'static_test' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native int cryptoTest();

    public native int eckeyTest();

    public native int ECDSATest();

    public native int RSATest();

    public native int SHATest();

    public native String CastTest();
}