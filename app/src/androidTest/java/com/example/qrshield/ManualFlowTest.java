package com.example.qrshield;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.closeSoftKeyboard;
import static androidx.test.espresso.action.ViewActions.typeText;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;

import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.ext.junit.rules.ActivityScenarioRule;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.example.qrshield.ui.home.MainActivity;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

/** Manual analysis reaches the shared result screen; opening is never automatic. */
@RunWith(AndroidJUnit4.class)
public class ManualFlowTest {

    @Rule
    public ActivityScenarioRule<MainActivity> rule = new ActivityScenarioRule<>(MainActivity.class);

    @Test
    public void javascriptSchemeShowsResultWithoutOpenButton() {
        onView(withId(R.id.btn_manual)).perform(click());
        onView(withId(R.id.input_text)).perform(typeText("javascript:alert(1)"), closeSoftKeyboard());
        onView(withId(R.id.btn_analyze)).perform(click());
        onView(withId(R.id.risk_badge)).check(matches(isDisplayed()));
        onView(withId(R.id.btn_open)).check(matches(withEffectiveVisibility(ViewMatchers.Visibility.GONE)));
    }

    @Test
    public void emptyInputShowsError() {
        onView(withId(R.id.btn_manual)).perform(click());
        onView(withId(R.id.btn_analyze)).perform(click());
        onView(withId(R.id.input_text)).check(matches(isDisplayed()));
    }

    @Test
    public void validHttpsOffersExplicitOpenAction() {
        onView(withId(R.id.btn_manual)).perform(click());
        onView(withId(R.id.input_text)).perform(typeText("https://example.com"), closeSoftKeyboard());
        onView(withId(R.id.btn_analyze)).perform(click());
        onView(withId(R.id.btn_open)).check(matches(isDisplayed()));
        onView(withText(R.string.open_button)).check(matches(isDisplayed()));
    }
}
