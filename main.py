import csv
from tempfile import NamedTemporaryFile
import shutil
import pandas as pd
import source_code as sc
from suggestion import suggest_email_domain
import whois
from popular_domains import emailDomains
import streamlit as st
from streamlit_extras.metric_cards import style_metric_cards

TIMER = None

st.set_page_config(
    page_title="Email verification",
    page_icon="✅",
    layout="centered",
)

def label_email(email):
    if not sc.is_valid_email(email):
        return "Invalid"
    if not sc.has_valid_mx_record(email.split('@')[1]):
        return "Invalid"
    if not sc.verify_email(email):
        return "Unknown"
    if sc.is_disposable(email.split('@')[1]):
        return "Risky"
    return "Valid"

def process_csv(input_file):
    # Read the uploaded file as a DataFrame
    if input_file:
        df = pd.read_csv(input_file, header=None)
        
        # Create a list to store the results
        results = []

        # Get the total number of emails
        total_emails = len(df)
        
        # Display the total number of emails to be processed
        st.info(f"Total emails to process: {total_emails}")

        # Initialize a progress bar
        progress_bar = st.progress(0)

        # Process each row in the input DataFrame
        for index, row in df.iterrows():
            email = row[0].strip()
            label = label_email(email)
            results.append([email, label])

            # Update progress bar
            progress = (index + 1) / total_emails
            progress_bar.progress(progress)

        # Create a new DataFrame for results
        result_df = pd.DataFrame(results, columns=['Email', 'Label'])
        result_df.index = range(1, len(result_df) + 1)  # Starting index from 1
        return result_df
    else:
        return pd.DataFrame(columns=['Email', 'Label'])

def process_xlsx(input_file):
    # Read the uploaded file as a DataFrame
    if input_file:
        df = pd.read_excel(input_file, header=None)
        
        # Create a list to store the results
        results = []

        # Get the total number of emails
        total_emails = len(df)
        
        # Display the total number of emails to be processed
        st.info(f"Total emails to process: {total_emails}")

        # Initialize a progress bar
        progress_bar = st.progress(0)

        # Process each row in the input DataFrame
        for index, row in df.iterrows():
            email = row[0].strip()
            label = label_email(email)
            results.append([email, label])

            # Update progress bar
            progress = (index + 1) / total_emails
            progress_bar.progress(progress)

        # Create a new DataFrame for results
        result_df = pd.DataFrame(results, columns=['Email', 'Label'])
        result_df.index = range(1, len(result_df) + 1)  # Starting index from 1
        return result_df
    else:
        return pd.DataFrame(columns=['Email', 'Label'])

def process_txt(input_file):
    # Read the uploaded file as text
    if input_file:
        input_text = input_file.read().decode("utf-8").splitlines()
        
        # Create a list to store the results
        results = []

        # Get the total number of emails
        total_emails = len(input_text)
        
        # Display the total number of emails to be processed
        st.info(f"Total emails to process: {total_emails}")

        # Initialize a progress bar
        progress_bar = st.progress(0)

        # Process each email in the input text
        for index, line in enumerate(input_text):
            email = line.strip()
            label = label_email(email)
            results.append([email, label])

            # Update progress bar
            progress = (index + 1) / total_emails
            progress_bar.progress(progress)

        # Create a new DataFrame for results
        result_df = pd.DataFrame(results, columns=['Email', 'Label'])
        result_df.index = range(1, len(result_df) + 1)  # Starting index from 1
        return result_df
    else:
        return pd.DataFrame(columns=['Email', 'Label'])

def main():

    with open('style.css') as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

    st.title("Email Verification Tool", help="This tool verifies the validity of an email address.")
    st.info("Results are accurate with 90% reliability.")

    t1, t2= st.tabs(["Single Email", "Bulk Email Processing"])

    with t1:
    # Single email verification

        email = st.text_input("Enter an email address:")
        
        if st.button("Verify"):
            with st.spinner('Verifying...'):
                result = {}

                # Syntax validation
                result['syntaxValidation'] = sc.is_valid_email(email)

                if result['syntaxValidation']:
                    domain_part = email.split('@')[1] if '@' in email else ''

                    if not domain_part:
                        st.error("Invalid email format. Please enter a valid email address.")
                    else:
                        # Additional validation for the domain part
                        if not sc.has_valid_mx_record(domain_part):
                            st.warning("Not valid: MX record not found.")
                            suggested_domains = suggest_email_domain(domain_part, emailDomains)
                            if suggested_domains:
                                st.info("Suggested Domains:")
                                for suggested_domain in suggested_domains:
                                    st.write(suggested_domain)
                            else:
                                st.warning("No suggested domains found.")
                        else:
                            # MX record validation
                            result['MXRecord'] = sc.has_valid_mx_record(domain_part)

                            # SMTP validation
                            if result['MXRecord']:
                                result['smtpConnection'] = sc.verify_email(email)
                            else:
                                result['smtpConnection'] = False

                            # Temporary domain check
                            result['is Temporary'] = sc.is_disposable(domain_part)

                            # Determine validity status and message
                            is_valid = (
                                result['syntaxValidation']
                                and result['MXRecord']
                                and result['smtpConnection']
                                and not result['is Temporary']
                            )

                            st.markdown("**Result:**")

                            # Display metric cards with reduced text size
                            col1, col2, col3 = st.columns(3)
                            col1.metric(label="Syntax", value=result['syntaxValidation'])
                            col2.metric(label="MxRecord", value=result['MXRecord'])
                            col3.metric(label="Is Temporary", value=result['is Temporary'])
                            style_metric_cards()
                            
                            # Show SMTP connection status as a warning
                            if not result['smtpConnection']:
                                st.warning("SMTP connection not established.")
                            
                            # Show domain details in an expander
                            with st.expander("See Domain Information"):
                                try:
                                    dm_info = whois.whois(domain_part)
                                    st.write("Registrar:", dm_info.registrar)
                                    st.write("Server:", dm_info.whois_server)
                                    st.write("Country:", dm_info.country)
                                except:
                                    st.error("Domain information retrieval failed.")
                            
                            # Show validity message
                            if is_valid:
                                st.success(f"{email} is a Valid email")
                            else:
                                st.error(f"{email} is a Invalid email")
                                if result['is Temporary']:
                                    st.text("It is a disposable email")

    with t2:
        # Bulk email processing
        st.header("Bulk Email Processing")
        input_file = st.file_uploader("Upload a CSV, XLSX, or TXT file", type=["csv", "xlsx", "txt"])
        if input_file:
            st.write("Processing...")
            if input_file.type == 'text/plain':
                df = process_txt(input_file)
            elif input_file.type == 'application/vnd.ms-excel':
                df = process_xlsx(input_file)
            else:
                df = process_csv(input_file)
            
            st.success("Processing completed. Displaying results:")
            st.dataframe(df)

if __name__ == "__main__":
    main()
