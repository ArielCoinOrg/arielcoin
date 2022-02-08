#include <qt/createcontract.h>
#include <qt/forms/ui_createcontract.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/rpcconsole.h>
#include <qt/execrpccommand.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <validation.h>
#include <util/moneystr.h>
#include <qt/addressfield.h>
#include <qt/abifunctionfield.h>
#include <qt/contractutil.h>
#include <qt/tabbarinfo.h>
#include <qt/contractresult.h>
#include <qt/sendcoinsdialog.h>
#include <qt/styleSheet.h>
#include <qt/hardwaresigntx.h>
#include <interfaces/node.h>
#include <node/ui_interface.h>

#include <QRegularExpressionValidator>

namespace CreateContract_NS
{
// Contract data names
static const QString PRC_COMMAND = "createcontract";
static const QString PARAM_BYTECODE = "bytecode";
static const QString PARAM_GASLIMIT = "gaslimit";
static const QString PARAM_GASPRICE = "gasprice";
static const QString PARAM_SENDER = "sender";

static const CAmount SINGLE_STEP = 0.00000001*COIN;
static const CAmount HIGH_GASPRICE = 0.001*COIN;
}
using namespace CreateContract_NS;

CreateContract::CreateContract(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::CreateContract),
    m_model(0),
    m_clientModel(0),
    m_execRPCCommand(0),
    m_ABIFunctionField(0),
    m_contractABI(0),
    m_tabInfo(0),
    m_results(1)
{
    // Setup ui components
    Q_UNUSED(platformStyle);
    ui->setupUi(this);

    // Set stylesheet
    SetObjectStyleSheet(ui->pushButtonClearAll, StyleSheetNames::ButtonDark);

    m_ABIFunctionField = new ABIFunctionField(platformStyle, ABIFunctionField::Create, ui->scrollAreaConstructor);
    ui->scrollAreaConstructor->setWidget(m_ABIFunctionField);
    ui->labelBytecode->setToolTip(tr("The bytecode of the contract"));
    ui->labelSenderAddress->setToolTip(tr("The qtum address that will be used to create the contract."));

    m_tabInfo = new TabBarInfo(ui->stackedWidget);
    m_tabInfo->addTab(0, tr("Create Contract"));

    // Set defaults
    ui->lineEditGasPrice->setValue(DEFAULT_GAS_PRICE);
    ui->lineEditGasPrice->setSingleStep(SINGLE_STEP);
    ui->lineEditGasLimit->setMinimum(MINIMUM_GAS_LIMIT);
    ui->lineEditGasLimit->setMaximum(DEFAULT_GAS_LIMIT_OP_CREATE);
    ui->lineEditGasLimit->setValue(DEFAULT_GAS_LIMIT_OP_CREATE);
    ui->pushButtonCreateContract->setEnabled(false);
    ui->lineEditSenderAddress->setSenderAddress(true);

    // Create new PRC command line interface
    QStringList lstMandatory;
    lstMandatory.append(PARAM_BYTECODE);
    QStringList lstOptional;
    lstOptional.append(PARAM_GASLIMIT);
    lstOptional.append(PARAM_GASPRICE);
    lstOptional.append(PARAM_SENDER);
    QMap<QString, QString> lstTranslations;
    lstTranslations[PARAM_BYTECODE] = ui->labelBytecode->text();
    lstTranslations[PARAM_GASLIMIT] = ui->labelGasLimit->text();
    lstTranslations[PARAM_GASPRICE] = ui->labelGasPrice->text();
    lstTranslations[PARAM_SENDER] = ui->labelSenderAddress->text();
    m_execRPCCommand = new ExecRPCCommand(PRC_COMMAND, lstMandatory, lstOptional, lstTranslations, this);
    m_contractABI = new ContractABI();

    // Connect signals with slots
    connect(ui->pushButtonClearAll, &QPushButton::clicked, this, &CreateContract::on_clearAllClicked);
    connect(ui->pushButtonCreateContract, &QPushButton::clicked, this, &CreateContract::on_createContractClicked);
    connect(ui->textEditBytecode, &QValidatedTextEdit::textChanged, this, &CreateContract::on_updateCreateButton);
    connect(ui->textEditInterface, &QValidatedTextEdit::textChanged, this, &CreateContract::on_newContractABI);
    connect(ui->stackedWidget, &QStackedWidget::currentChanged, this, &CreateContract::on_updateCreateButton);

    // Set bytecode validator
    QRegularExpression regEx;
    regEx.setPattern(paternHex);
    QRegularExpressionValidator *bytecodeValidator = new QRegularExpressionValidator(ui->textEditBytecode);
    bytecodeValidator->setRegularExpression(regEx);
    ui->textEditBytecode->setCheckValidator(bytecodeValidator);
}

CreateContract::~CreateContract()
{
    delete m_contractABI;
    delete ui;
}

void CreateContract::setModel(WalletModel *_model)
{
    m_model = _model;
    ui->lineEditSenderAddress->setWalletModel(m_model);

    if (m_model && m_model->getOptionsModel())
        connect(m_model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &CreateContract::updateDisplayUnit);

    // update the display unit, to not use the default ("QTUM")
    updateDisplayUnit();

    bCreateUnsigned = m_model->createUnsigned();

    if (bCreateUnsigned) {
        ui->pushButtonCreateContract->setText(tr("Cr&eate Unsigned"));
        ui->pushButtonCreateContract->setToolTip(tr("Creates a Partially Signed Qtum Transaction (PSBT) for use with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
    }
}

bool CreateContract::isValidBytecode()
{
    ui->textEditBytecode->checkValidity();
    return ui->textEditBytecode->isValid();
}

bool CreateContract::isValidInterfaceABI()
{
    ui->textEditInterface->checkValidity();
    return ui->textEditInterface->isValid();
}

bool CreateContract::isDataValid()
{
    bool dataValid = true;
    int func = m_ABIFunctionField->getSelectedFunction();
    bool funcValid = func == -1 ? true : m_ABIFunctionField->isValid();

    if(!isValidBytecode())
        dataValid = false;
    if(!isValidInterfaceABI())
        dataValid = false;
    if(!funcValid)
        dataValid = false;

    return dataValid;
}

void CreateContract::setClientModel(ClientModel *_clientModel)
{
    m_clientModel = _clientModel;

    if (m_clientModel)
    {
        connect(m_clientModel, SIGNAL(gasInfoChanged(quint64, quint64, quint64)), this, SLOT(on_gasInfoChanged(quint64, quint64, quint64)));
    }
}

void CreateContract::on_clearAllClicked()
{
    ui->textEditBytecode->clear();
    ui->lineEditGasLimit->setValue(DEFAULT_GAS_LIMIT_OP_CREATE);
    ui->lineEditGasPrice->setValue(DEFAULT_GAS_PRICE);
    ui->lineEditSenderAddress->setCurrentIndex(-1);
    ui->textEditInterface->clear();
    m_tabInfo->clear();
}

void CreateContract::on_createContractClicked()
{
    if(isDataValid())
    {
        WalletModel::UnlockContext ctx(m_model->requestUnlock());
        if(!ctx.isValid())
        {
            return;
        }

        // Initialize variables
        QMap<QString, QString> lstParams;
        QVariant result;
        QString errorMessage;
        QString resultJson;
        int unit = BitcoinUnits::BTC;
        uint64_t gasLimit = ui->lineEditGasLimit->value();
        CAmount gasPrice = ui->lineEditGasPrice->value();
        int func = m_ABIFunctionField->getSelectedFunction();

        // Check for high gas price
        if(gasPrice > HIGH_GASPRICE)
        {
            QString message = tr("The Gas Price is too high, are you sure you want to possibly spend a max of %1 for this transaction?");
            if(QMessageBox::question(this, tr("High Gas price"), message.arg(BitcoinUnits::formatWithUnit(unit, gasLimit * gasPrice))) == QMessageBox::No)
                return;
        }

        // Append params to the list
        QString bytecode = ui->textEditBytecode->toPlainText() + toDataHex(func, errorMessage);
        ExecRPCCommand::appendParam(lstParams, PARAM_BYTECODE, bytecode);
        ExecRPCCommand::appendParam(lstParams, PARAM_GASLIMIT, QString::number(gasLimit));
        ExecRPCCommand::appendParam(lstParams, PARAM_GASPRICE, BitcoinUnits::format(unit, gasPrice, false, BitcoinUnits::SeparatorStyle::NEVER));
        ExecRPCCommand::appendParam(lstParams, PARAM_SENDER, ui->lineEditSenderAddress->currentText());

        QString questionString;
        if (bCreateUnsigned) {
            questionString.append(tr("Do you want to draft this create contract transaction?"));
            questionString.append("<br /><span style='font-size:10pt;'>");
            questionString.append(tr("This will produce a Partially Signed Qtum Transaction (PSBT) which you can copy and then sign with e.g. an offline %1 wallet, or a PSBT-compatible hardware wallet.").arg(PACKAGE_NAME));
            questionString.append("</span>");
        } else {
            questionString.append(tr("Are you sure you want to create contract? <br />"));
        }

        const QString confirmation = bCreateUnsigned ? tr("Confirm contract creation proposal.") : tr("Confirm contract creation.");
        const QString confirmButtonText = bCreateUnsigned ? tr("Copy PSBT to clipboard") : tr("Send");
        SendConfirmationDialog confirmationDialog(confirmation, questionString, "", "", SEND_CONFIRM_DELAY, confirmButtonText, this);
        confirmationDialog.exec();
        QMessageBox::StandardButton retval = (QMessageBox::StandardButton)confirmationDialog.result();
        if(retval == QMessageBox::Yes)
        {
            // Execute RPC command line
            if(errorMessage.isEmpty() && m_execRPCCommand->exec(m_model->node(), m_model, lstParams, result, resultJson, errorMessage))
            {
                if(bCreateUnsigned)
                {
                    QVariantMap variantMap = result.toMap();
                    GUIUtil::setClipboard(variantMap.value("psbt").toString());
                    Q_EMIT message(tr("PSBT copied"), "Copied to clipboard", CClientUIInterface::MSG_INFORMATION);
                }
                else
                {
                    bool isSent = true;
                    if(m_model->getSignPsbtWithHwiTool())
                    {
                        QVariantMap variantMap = result.toMap();
                        QString psbt = variantMap.value("psbt").toString();
                        if(!HardwareSignTx::process(this, m_model, psbt, variantMap))
                            isSent = false;
                        else
                            result = variantMap;
                    }

                    if(isSent)
                    {
                        ContractResult *widgetResult = new ContractResult(ui->stackedWidget);
                        widgetResult->setResultData(result, FunctionABI(), QList<QStringList>(), ContractResult::CreateResult);
                        ui->stackedWidget->addWidget(widgetResult);
                        int position = ui->stackedWidget->count() - 1;
                        m_results = position == 1 ? 1 : m_results + 1;

                        m_tabInfo->addTab(position, tr("Result %1").arg(m_results));
                        m_tabInfo->setCurrent(position);
                    }
                }
            }
            else
            {
                QMessageBox::warning(this, tr("Create contract"), errorMessage);
            }
        }
    }
}

void CreateContract::on_gasInfoChanged(quint64 blockGasLimit, quint64 minGasPrice, quint64 nGasPrice)
{
    Q_UNUSED(nGasPrice);
    ui->labelGasLimit->setToolTip(tr("Gas limit. Default = %1, Max = %2").arg(DEFAULT_GAS_LIMIT_OP_CREATE).arg(blockGasLimit));
    ui->labelGasPrice->setToolTip(tr("Gas price: QTUM price per gas unit. Default = %1, Min = %2").arg(QString::fromStdString(FormatMoney(DEFAULT_GAS_PRICE))).arg(QString::fromStdString(FormatMoney(minGasPrice))));
    ui->lineEditGasPrice->SetMinValue(minGasPrice);
    ui->lineEditGasLimit->setMaximum(blockGasLimit);
}

void CreateContract::on_updateCreateButton()
{
    bool enabled = true;
    if(ui->textEditBytecode->toPlainText().isEmpty())
    {
        enabled = false;
    }
    enabled &= ui->stackedWidget->currentIndex() == 0;

    ui->pushButtonCreateContract->setEnabled(enabled);
}

void CreateContract::on_newContractABI()
{
    std::string json_data = ui->textEditInterface->toPlainText().toStdString();
    if(!m_contractABI->loads(json_data))
    {
        m_contractABI->clean();
        ui->textEditInterface->setIsValidManually(false);
    }
    else
    {
        ui->textEditInterface->setIsValidManually(true);
    }
    m_ABIFunctionField->setContractABI(m_contractABI);

    on_updateCreateButton();
}

void CreateContract::updateDisplayUnit()
{
    if(m_model && m_model->getOptionsModel())
    {
        // Update gasPriceAmount with the current unit
        ui->lineEditGasPrice->setDisplayUnit(m_model->getOptionsModel()->getDisplayUnit());
    }
}

QString CreateContract::toDataHex(int func, QString& errorMessage)
{
    if(func == -1 || m_ABIFunctionField == NULL || m_contractABI == NULL)
    {
        return "";
    }

    std::string strData;
    std::vector<std::vector<std::string>> values = m_ABIFunctionField->getValuesVector();
    FunctionABI function = m_contractABI->functions[func];
    std::vector<ParameterABI::ErrorType> errors;
    if(function.abiIn(values, strData, errors))
    {
        return QString::fromStdString(strData);
    }
    else
    {
        errorMessage = ContractUtil::errorMessage(function, errors, true);
    }
    return "";
}
